#!/usr/bin/env python3
# /opt/openvpn-panel/openvpn.py

import os
import re
import hmac
import time
import shutil
import zipfile
import secrets
import subprocess
import ipaddress
from pathlib import Path, PurePosixPath
from functools import wraps
from datetime import datetime

from flask import (
    Flask,
    request,
    redirect,
    url_for,
    session,
    flash,
    jsonify,
    abort,
    send_file,
    render_template_string,
)
from werkzeug.utils import secure_filename


APP_NAME = "Mirako OpenVPN Panel"

OPENVPN_CONFIG_DIR = Path(os.environ.get("OPENVPN_CONFIG_DIR", "/etc/openvpn/client"))
BACKUP_DIR = Path(os.environ.get("OPENVPN_BACKUP_DIR", "/var/backups/openvpn-panel"))

PANEL_USER = os.environ.get("OPENVPN_PANEL_USER", "admin")
DEFAULT_PASSWORD = "admin123"
PANEL_PASSWORD = os.environ.get("OPENVPN_PANEL_PASSWORD", DEFAULT_PASSWORD)

HOST = os.environ.get("OPENVPN_PANEL_HOST", "0.0.0.0")
PORT = int(os.environ.get("OPENVPN_PANEL_PORT", "5050"))
MAX_UPLOAD_MB = int(os.environ.get("OPENVPN_PANEL_MAX_UPLOAD_MB", "32"))

# Interface que ENTREGA internet aos clientes. Exemplos: wlan0, eth1, br0, ap0.
DEFAULT_SHARE_LAN_IF = os.environ.get("OPENVPN_SHARE_LAN_IF", "")
# Interface VPN. Se vazio/auto, o painel tenta achar tun0/tap0/ovpn.
DEFAULT_SHARE_VPN_IF = os.environ.get("OPENVPN_SHARE_VPN_IF", "auto")
# Aplica NAT automaticamente depois de conectar/reiniciar uma VPN quando LAN_IF estiver definido.
AUTO_SHARE_ON_START = os.environ.get("OPENVPN_AUTO_SHARE_ON_START", "0") == "1"

# Modo normal: internet comum entra por uma interface WAN e sai para clientes pela LAN/AP.
# Exemplo comum no seu caso: WAN=end0 e LAN=wlan0.
DEFAULT_NORMAL_WAN_IF = os.environ.get("OPENVPN_NORMAL_WAN_IF", "end0")
DEFAULT_NORMAL_LAN_IF = os.environ.get("OPENVPN_NORMAL_LAN_IF", DEFAULT_SHARE_LAN_IF or "wlan0")
# Gateway IPv4 da internet normal. Deixe vazio para detectar automaticamente.
# Exemplo: OPENVPN_NORMAL_GATEWAY=192.168.1.1
DEFAULT_NORMAL_GATEWAY = os.environ.get("OPENVPN_NORMAL_GATEWAY", "").strip()
# Tabela de roteamento usada para forçar clientes da LAN a saírem pela WAN normal,
# mesmo se a VPN tiver criado redirect-gateway no roteamento principal.
NORMAL_ROUTE_TABLE = int(os.environ.get("OPENVPN_NORMAL_ROUTE_TABLE", "100"))
NORMAL_ROUTE_PRIORITY = int(os.environ.get("OPENVPN_NORMAL_ROUTE_PRIORITY", "10010"))

VALID_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
VALID_IFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,32}$")

CONFIG_EXTENSIONS = {".ovpn", ".conf"}
SUPPORT_EXTENSIONS = {".crt", ".key", ".pem", ".p12", ".txt", ".auth", ".pass", ".ca", ".tlsauth"}
ZIP_EXTENSIONS = {".zip"}
ALLOWED_EXTENSIONS = CONFIG_EXTENSIONS | SUPPORT_EXTENSIONS | ZIP_EXTENSIONS

app = Flask(__name__)
app.secret_key = os.environ.get("OPENVPN_PANEL_SECRET", secrets.token_hex(32))
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024


def ensure_directories():
    OPENVPN_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)


def now_stamp():
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def run_cmd(args, timeout=15):
    try:
        p = subprocess.run(args, text=True, capture_output=True, timeout=timeout)
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except subprocess.TimeoutExpired:
        return 124, "", f"Timeout executando: {' '.join(args)}"
    except Exception as e:
        return 1, "", str(e)


def command_exists(cmd):
    return shutil.which(cmd) is not None


def sanitize_config_name(name):
    name = secure_filename(name or "").strip()
    name = Path(name).stem
    name = re.sub(r"[^A-Za-z0-9_.-]", "_", name).strip("._-")
    if not name:
        raise ValueError("Nome da configuração inválido.")
    name = name[:64]
    if not VALID_NAME_RE.match(name):
        raise ValueError("Nome da configuração contém caracteres inválidos.")
    return name


def validate_name_or_404(name):
    if not VALID_NAME_RE.match(name or ""):
        abort(404)
    return name


def validate_iface(name):
    name = (name or "").strip()
    if not VALID_IFACE_RE.match(name):
        raise ValueError(f"Interface inválida: {name}")
    return name


def config_path(name):
    validate_name_or_404(name)
    return OPENVPN_CONFIG_DIR / f"{name}.conf"


def unit_name(name):
    validate_name_or_404(name)
    return f"openvpn-client@{name}.service"


def backup_file(path):
    if path.exists():
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        backup = BACKUP_DIR / f"{path.name}.{now_stamp()}.bak"
        shutil.copy2(path, backup)
        return backup
    return None


def csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


def check_csrf():
    sent = request.form.get("csrf", "")
    real = session.get("_csrf_token", "")
    if not real or not hmac.compare_digest(sent, real):
        abort(403)


app.jinja_env.globals["csrf_token"] = csrf_token


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper


def ext_of(filename):
    return Path(filename or "").suffix.lower()


def is_allowed_file(filename):
    return ext_of(filename) in ALLOWED_EXTENSIONS


def read_text_safe(path, max_chars=20000):
    try:
        return path.read_text(encoding="utf-8", errors="ignore")[:max_chars]
    except Exception:
        return ""


def parse_config_summary(path):
    summary = {"remote": "-", "proto": "-", "dev": "-", "auth_warning": False, "has_inline_keys": False}
    text = read_text_safe(path, max_chars=50000)
    remotes = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        parts = line.split()
        key = parts[0].lower()
        if key == "remote" and len(parts) >= 2:
            remotes.append(" ".join(parts[1:4]))
        elif key == "proto" and len(parts) >= 2:
            summary["proto"] = parts[1]
        elif key == "dev" and len(parts) >= 2:
            summary["dev"] = parts[1]
        elif key == "auth-user-pass" and len(parts) == 1:
            summary["auth_warning"] = True
        elif key in {"<ca>", "<cert>", "<key>", "<tls-crypt>", "<tls-auth>"}:
            summary["has_inline_keys"] = True
    if remotes:
        summary["remote"] = ", ".join(remotes[:3])
    return summary


def parse_systemctl_show(output):
    data = {}
    for line in output.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            data[k] = v
    return data


def get_unit_state(name):
    unit = unit_name(name)
    rc_show, out_show, err_show = run_cmd([
        "systemctl", "show", unit, "--no-page",
        "-p", "LoadState", "-p", "ActiveState", "-p", "SubState",
        "-p", "MainPID", "-p", "UnitFileState", "-p", "ExecMainStatus",
        "-p", "ExecMainStartTimestamp",
    ], timeout=8)
    show = parse_systemctl_show(out_show)
    rc_active, out_active, _ = run_cmd(["systemctl", "is-active", unit], timeout=5)
    rc_enabled, out_enabled, _ = run_cmd(["systemctl", "is-enabled", unit], timeout=5)
    active = out_active.strip() or show.get("ActiveState", "unknown")
    enabled = out_enabled.strip() or show.get("UnitFileState", "unknown")
    return {
        "unit": unit,
        "active": active,
        "enabled": enabled,
        "load_state": show.get("LoadState", "unknown"),
        "sub_state": show.get("SubState", "unknown"),
        "main_pid": show.get("MainPID", "0"),
        "exec_status": show.get("ExecMainStatus", ""),
        "start_time": show.get("ExecMainStartTimestamp", ""),
        "show_error": err_show if rc_show != 0 else "",
        "active_rc": rc_active,
        "enabled_rc": rc_enabled,
    }


def get_all_interfaces():
    rc, out, _ = run_cmd(["ip", "-o", "link", "show"], timeout=5)
    interfaces = []
    if rc != 0:
        return interfaces
    for line in out.splitlines():
        m = re.match(r"^\d+:\s+([^:@]+)", line)
        if m:
            interfaces.append(m.group(1))
    return sorted(set(interfaces))


def get_vpn_interfaces():
    rc, out, _ = run_cmd(["ip", "-o", "addr", "show"], timeout=5)
    interfaces = []
    if rc != 0:
        return interfaces
    for line in out.splitlines():
        m = re.match(r"^\d+:\s+([^\s]+)\s+(inet6?|link/[^ ]+)\s+([^\s]+)", line)
        if not m:
            continue
        iface = m.group(1).split("@", 1)[0]
        family = m.group(2)
        address = m.group(3)
        if iface.startswith(("tun", "tap", "ovpn")):
            interfaces.append({"iface": iface, "family": family, "address": address})
    return interfaces


def detect_vpn_iface(preferred="auto"):
    preferred = (preferred or "auto").strip()
    if preferred != "auto":
        return validate_iface(preferred)
    vpn_ifs = get_vpn_interfaces()
    for item in vpn_ifs:
        if item["family"] == "inet":
            return item["iface"]
    return vpn_ifs[0]["iface"] if vpn_ifs else "tun0"


def get_routes_summary():
    rc, out, _ = run_cmd(["ip", "route"], timeout=5)
    if rc != 0:
        return []
    return [line for line in out.splitlines() if any(x in line for x in ["tun", "tap", "ovpn"] )][:20]


def get_default_route():
    rc, out, _ = run_cmd(["ip", "route", "show", "default"], timeout=5)
    if rc != 0 or not out:
        return "-"
    return out.splitlines()[0]


# ==========================================================
# NAT / COMPARTILHAMENTO DE INTERNET PELA VPN
# ==========================================================

def iptables_rule_exists(table, rule):
    args = ["iptables"]
    if table:
        args += ["-t", table]
    args += ["-C"] + rule
    rc, _, _ = run_cmd(args, timeout=5)
    return rc == 0


def iptables_add_once(table, rule):
    if iptables_rule_exists(table, rule):
        return False, "já existia"
    args = ["iptables"]
    if table:
        args += ["-t", table]
    args += ["-A"] + rule
    rc, out, err = run_cmd(args, timeout=10)
    if rc != 0:
        raise RuntimeError(err or out or "Erro ao adicionar regra iptables")
    return True, "adicionada"


def iptables_delete_all(table, rule):
    removed = 0
    last_error = ""
    for _ in range(30):
        if not iptables_rule_exists(table, rule):
            break
        args = ["iptables"]
        if table:
            args += ["-t", table]
        args += ["-D"] + rule
        rc, out, err = run_cmd(args, timeout=10)
        if rc != 0:
            last_error = err or out
            break
        removed += 1
    return removed, last_error


def enable_ipv4_forward():
    messages = []
    rc, out, err = run_cmd(["sysctl", "-w", "net.ipv4.ip_forward=1"], timeout=5)
    if rc != 0:
        raise RuntimeError(err or out or "Erro ao ativar net.ipv4.ip_forward")
    messages.append(out or "net.ipv4.ip_forward=1")

    conf = Path("/etc/sysctl.d/99-openvpn-panel-forward.conf")
    conf.write_text("net.ipv4.ip_forward=1\n", encoding="utf-8")
    messages.append(f"persistência criada em {conf}")
    return messages


def get_ip_forward_value():
    try:
        return Path("/proc/sys/net/ipv4/ip_forward").read_text().strip()
    except Exception:
        return "unknown"


def vpn_share_rules(lan_if, vpn_if):
    lan_if = validate_iface(lan_if)
    vpn_if = validate_iface(vpn_if)
    return [
        {
            "table": "nat",
            "rule": ["POSTROUTING", "-o", vpn_if, "-j", "MASQUERADE"],
            "name": f"NAT/MASQUERADE saída {vpn_if}",
        },
        {
            "table": None,
            "rule": ["FORWARD", "-i", lan_if, "-o", vpn_if, "-j", "ACCEPT"],
            "name": f"FORWARD clientes {lan_if} -> VPN {vpn_if}",
        },
        {
            "table": None,
            "rule": ["FORWARD", "-i", vpn_if, "-o", lan_if, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
            "name": f"FORWARD retorno {vpn_if} -> {lan_if}",
        },
        {
            "table": "mangle",
            "rule": ["FORWARD", "-o", vpn_if, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"],
            "name": "TCP MSS clamp para evitar sites travando por MTU",
        },
    ]


def apply_vpn_sharing(lan_if, vpn_if="auto"):
    if not command_exists("iptables"):
        raise RuntimeError("iptables não encontrado. Instale com: sudo apt install iptables")

    lan_if = validate_iface(lan_if)
    vpn_if = detect_vpn_iface(vpn_if)
    messages = []
    messages.extend(enable_ipv4_forward())

    for item in vpn_share_rules(lan_if, vpn_if):
        changed, status = iptables_add_once(item["table"], item["rule"])
        messages.append(f"{item['name']}: {status}")

    return {
        "lan_if": lan_if,
        "vpn_if": vpn_if,
        "messages": messages,
    }


def disable_vpn_sharing(lan_if, vpn_if="auto"):
    if not command_exists("iptables"):
        raise RuntimeError("iptables não encontrado.")

    lan_if = validate_iface(lan_if)
    vpn_if = detect_vpn_iface(vpn_if)
    messages = []

    # Remove em ordem inversa.
    for item in reversed(vpn_share_rules(lan_if, vpn_if)):
        removed, err = iptables_delete_all(item["table"], item["rule"])
        if err:
            messages.append(f"{item['name']}: erro {err}")
        else:
            messages.append(f"{item['name']}: removidas {removed}")

    return {
        "lan_if": lan_if,
        "vpn_if": vpn_if,
        "messages": messages,
    }


def save_firewall_rules():
    if command_exists("netfilter-persistent"):
        rc, out, err = run_cmd(["netfilter-persistent", "save"], timeout=20)
        if rc != 0:
            raise RuntimeError(err or out or "Erro ao salvar com netfilter-persistent")
        return out or "Regras salvas com netfilter-persistent."

    if command_exists("iptables-save"):
        dest = Path("/etc/iptables")
        dest.mkdir(parents=True, exist_ok=True)
        path = dest / "rules.v4"
        with path.open("w", encoding="utf-8") as f:
            p = subprocess.run(["iptables-save"], text=True, stdout=f, stderr=subprocess.PIPE, timeout=10)
        if p.returncode != 0:
            raise RuntimeError(p.stderr.strip() or "Erro ao executar iptables-save")
        return f"Regras salvas em {path}. Instale iptables-persistent para restaurar no boot."

    raise RuntimeError("Não encontrei netfilter-persistent nem iptables-save.")


def get_vpn_sharing_status(lan_if=None, vpn_if=None):
    lan_if = (lan_if or DEFAULT_SHARE_LAN_IF or "").strip()
    vpn_if_input = (vpn_if or DEFAULT_SHARE_VPN_IF or "auto").strip()
    detected_vpn_if = detect_vpn_iface(vpn_if_input)

    status = {
        "lan_if": lan_if,
        "vpn_if": detected_vpn_if,
        "vpn_if_input": vpn_if_input,
        "ip_forward": get_ip_forward_value(),
        "rules": [],
        "ok": False,
        "missing_lan": not bool(lan_if),
        "default_route": get_default_route(),
    }

    if not lan_if:
        return status

    try:
        for item in vpn_share_rules(lan_if, detected_vpn_if):
            exists = iptables_rule_exists(item["table"], item["rule"]) if command_exists("iptables") else False
            status["rules"].append({"name": item["name"], "exists": exists})
        status["ok"] = status["ip_forward"] == "1" and all(r["exists"] for r in status["rules"])
    except Exception as e:
        status["error"] = str(e)

    return status



# ==========================================================
# MODO NORMAL: COMPARTILHAR INTERNET SEM PASSAR PELA VPN
# ==========================================================


def get_iface_ipv4_entries(iface):
    iface = validate_iface(iface)
    rc, out, _ = run_cmd(["ip", "-o", "-4", "addr", "show", "dev", iface], timeout=5)
    entries = []
    if rc != 0:
        return entries
    for line in out.splitlines():
        parts = line.split()
        if "inet" in parts:
            idx = parts.index("inet")
            if idx + 1 < len(parts):
                raw = parts[idx + 1]
                item = {"cidr": raw, "network": raw, "address": raw.split("/", 1)[0]}
                try:
                    item["network"] = str(ipaddress.ip_network(raw, strict=False))
                except Exception:
                    pass
                entries.append(item)
    return entries


def get_iface_ipv4_cidrs(iface):
    return sorted(set(item["network"] for item in get_iface_ipv4_entries(iface)))


def get_iface_ipv4_addresses(iface):
    return sorted(set(item["cidr"] for item in get_iface_ipv4_entries(iface)))


def get_iface_ipv6_addresses(iface):
    iface = validate_iface(iface)
    rc, out, _ = run_cmd(["ip", "-o", "-6", "addr", "show", "dev", iface], timeout=5)
    addrs = []
    if rc != 0:
        return addrs
    for line in out.splitlines():
        parts = line.split()
        if "inet6" in parts:
            idx = parts.index("inet6")
            if idx + 1 < len(parts):
                addrs.append(parts[idx + 1])
    return sorted(set(addrs))


def get_iface_state(iface):
    iface = validate_iface(iface)
    rc, out, _ = run_cmd(["ip", "-o", "link", "show", "dev", iface], timeout=5)
    if rc != 0 or not out:
        return "unknown"
    m = re.search(r"state\s+(\S+)", out)
    return m.group(1) if m else "unknown"


def valid_ipv4(ip):
    try:
        ipaddress.ip_address(ip)
        return "." in ip
    except Exception:
        return False


def get_default_gateway_for_iface(iface, manual_gateway=""):
    iface = validate_iface(iface)
    manual_gateway = (manual_gateway or "").strip()

    if manual_gateway:
        if not valid_ipv4(manual_gateway):
            raise RuntimeError(f"Gateway IPv4 inválido: {manual_gateway}")
        return manual_gateway

    # Primeiro tenta achar uma rota default explícita nessa interface.
    rc, out, _ = run_cmd(["ip", "-4", "route", "show", "default", "dev", iface], timeout=5)
    if rc == 0 and out:
        for line in out.splitlines():
            parts = line.split()
            if "via" in parts:
                idx = parts.index("via")
                if idx + 1 < len(parts):
                    return parts[idx + 1]
            if "dev" in parts and iface in parts:
                return ""

    # Depois procura qualquer default IPv4 que use essa interface.
    rc, out, _ = run_cmd(["ip", "-4", "route", "show", "default"], timeout=5)
    if rc == 0 and out:
        for line in out.splitlines():
            parts = line.split()
            if "dev" in parts:
                idx_dev = parts.index("dev")
                if idx_dev + 1 < len(parts) and parts[idx_dev + 1] == iface:
                    if "via" in parts:
                        idx_via = parts.index("via")
                        if idx_via + 1 < len(parts):
                            return parts[idx_via + 1]
                    return ""

    return None


def renew_wan_ipv4(iface):
    iface = validate_iface(iface)
    messages = []
    rc, out, err = run_cmd(["ip", "link", "set", iface, "up"], timeout=10)
    if rc != 0:
        raise RuntimeError(err or out or f"Erro ao ativar interface {iface}")
    messages.append(f"interface {iface} ativada")

    if command_exists("dhclient"):
        run_cmd(["dhclient", "-4", "-r", iface], timeout=20)
        rc, out, err = run_cmd(["dhclient", "-4", "-v", iface], timeout=45)
        if rc != 0:
            raise RuntimeError(err or out or f"dhclient falhou em {iface}")
        messages.append(out or f"DHCP IPv4 renovado em {iface}")
    elif command_exists("udhcpc"):
        rc, out, err = run_cmd(["udhcpc", "-i", iface, "-q", "-n"], timeout=45)
        if rc != 0:
            raise RuntimeError(err or out or f"udhcpc falhou em {iface}")
        messages.append(out or f"DHCP IPv4 renovado em {iface}")
    elif command_exists("networkctl"):
        rc, out, err = run_cmd(["networkctl", "renew", iface], timeout=20)
        if rc != 0:
            raise RuntimeError(err or out or f"networkctl renew falhou em {iface}")
        messages.append(out or f"networkctl renew executado em {iface}")
    else:
        raise RuntimeError("Nenhum cliente DHCP encontrado. Instale isc-dhcp-client ou udhcpc, ou configure IPv4 estático na WAN.")

    messages.append(f"IPv4 atual {iface}: {', '.join(get_iface_ipv4_addresses(iface)) or 'sem IPv4'}")
    messages.append(f"rota default atual: {get_default_route()}")
    return messages


def normal_share_rules(wan_if, lan_if):
    wan_if = validate_iface(wan_if)
    lan_if = validate_iface(lan_if)
    return [
        {
            "table": "nat",
            "rule": ["POSTROUTING", "-o", wan_if, "-j", "MASQUERADE"],
            "name": f"NAT/MASQUERADE internet normal saída {wan_if}",
        },
        {
            "table": None,
            "rule": ["FORWARD", "-i", lan_if, "-o", wan_if, "-j", "ACCEPT"],
            "name": f"FORWARD clientes {lan_if} -> internet normal {wan_if}",
        },
        {
            "table": None,
            "rule": ["FORWARD", "-i", wan_if, "-o", lan_if, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
            "name": f"FORWARD retorno internet normal {wan_if} -> {lan_if}",
        },
        {
            "table": "mangle",
            "rule": ["FORWARD", "-o", wan_if, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"],
            "name": "TCP MSS clamp para internet normal",
        },
    ]


def ip_rule_exists(rule_parts):
    rc, out, _ = run_cmd(["ip", "rule", "show"], timeout=5)
    if rc != 0:
        return False

    # ip rule add usa "table", mas ip rule show costuma exibir "lookup".
    try:
        src = rule_parts[rule_parts.index("from") + 1]
        prio = rule_parts[rule_parts.index("priority") + 1]
        table = rule_parts[rule_parts.index("table") + 1]
    except Exception:
        needle = " ".join(rule_parts)
        return needle in out

    for line in out.splitlines():
        if not line.startswith(f"{prio}:"):
            continue
        if f"from {src}" not in line:
            continue
        if f"lookup {table}" in line or f"table {table}" in line:
            return True
    return False


def ip_rule_delete_all(rule_parts):
    removed = 0
    last_error = ""
    for _ in range(30):
        if not ip_rule_exists(rule_parts):
            break
        rc, out, err = run_cmd(["ip", "rule", "del"] + rule_parts, timeout=10)
        if rc != 0:
            last_error = err or out
            break
        removed += 1
    return removed, last_error


def ip_rule_add_once(rule_parts):
    if ip_rule_exists(rule_parts):
        return False, "já existia"
    rc, out, err = run_cmd(["ip", "rule", "add"] + rule_parts, timeout=10)
    if rc != 0:
        raise RuntimeError(err or out or "Erro ao adicionar ip rule")
    return True, "adicionada"


def normal_policy_rule_parts(lan_cidr):
    return ["from", lan_cidr, "priority", str(NORMAL_ROUTE_PRIORITY), "table", str(NORMAL_ROUTE_TABLE)]


def apply_normal_policy_routing(wan_if, lan_if, manual_gateway=""):
    wan_if = validate_iface(wan_if)
    lan_if = validate_iface(lan_if)
    messages = []

    lan_cidrs = get_iface_ipv4_cidrs(lan_if)
    if not lan_cidrs:
        raise RuntimeError(f"A LAN {lan_if} não tem IPv4. Configure um IP, exemplo 192.168.40.1/24, antes de compartilhar internet.")

    wan_ipv4 = get_iface_ipv4_addresses(wan_if)
    if not wan_ipv4:
        wan_ipv6 = get_iface_ipv6_addresses(wan_if)
        extra = f" IPv6 encontrado: {', '.join(wan_ipv6)}." if wan_ipv6 else ""
        raise RuntimeError(
            f"A WAN {wan_if} não tem IPv4, então não existe internet IPv4 para compartilhar por NAT."
            f"{extra} Rode DHCP IPv4 na {wan_if} ou configure IPv4 estático/gateway manual."
        )

    gateway = get_default_gateway_for_iface(wan_if, manual_gateway)
    if gateway is None:
        raise RuntimeError(
            f"Não encontrei rota default/gateway IPv4 para {wan_if}. "
            f"Informe o gateway manual no painel, exemplo 192.168.1.1, ou renove o DHCP IPv4 da WAN."
        )

    # Limpa a tabela dedicada antes de recriar a rota normal.
    run_cmd(["ip", "route", "flush", "table", str(NORMAL_ROUTE_TABLE)], timeout=10)

    if gateway:
        rc, out, err = run_cmd(["ip", "route", "replace", "default", "via", gateway, "dev", wan_if, "table", str(NORMAL_ROUTE_TABLE)], timeout=10)
        route_msg = f"default via {gateway} dev {wan_if} table {NORMAL_ROUTE_TABLE}"
    else:
        rc, out, err = run_cmd(["ip", "route", "replace", "default", "dev", wan_if, "table", str(NORMAL_ROUTE_TABLE)], timeout=10)
        route_msg = f"default dev {wan_if} table {NORMAL_ROUTE_TABLE}"

    if rc != 0:
        raise RuntimeError(err or out or "Erro ao criar rota normal dedicada")

    messages.append(f"rota normal dedicada: {route_msg}")

    for cidr in lan_cidrs:
        parts = normal_policy_rule_parts(cidr)
        _, status = ip_rule_add_once(parts)
        messages.append(f"policy route clientes {cidr}: {status}")

    return messages


def remove_normal_policy_routing(lan_if):
    lan_if = validate_iface(lan_if)
    messages = []
    lan_cidrs = get_iface_ipv4_cidrs(lan_if)

    for cidr in lan_cidrs:
        removed, err = ip_rule_delete_all(normal_policy_rule_parts(cidr))
        if err:
            messages.append(f"policy route {cidr}: erro {err}")
        else:
            messages.append(f"policy route {cidr}: removidas {removed}")

    rc, out, err = run_cmd(["ip", "route", "flush", "table", str(NORMAL_ROUTE_TABLE)], timeout=10)
    if rc == 0:
        messages.append(f"tabela de rota {NORMAL_ROUTE_TABLE}: limpa")
    else:
        messages.append(f"tabela de rota {NORMAL_ROUTE_TABLE}: {err or out}")

    return messages


def apply_normal_sharing(wan_if, lan_if, remove_vpn=True, manual_gateway=""):
    if not command_exists("iptables"):
        raise RuntimeError("iptables não encontrado. Instale com: sudo apt install iptables")

    wan_if = validate_iface(wan_if)
    lan_if = validate_iface(lan_if)
    messages = []
    messages.extend(enable_ipv4_forward())

    if remove_vpn:
        try:
            vpn_if = detect_vpn_iface(DEFAULT_SHARE_VPN_IF)
            removed = disable_vpn_sharing(lan_if, vpn_if)
            messages.append(f"regras VPN removidas para voltar ao normal: {removed['lan_if']} -> {removed['vpn_if']}")
        except Exception as e:
            messages.append(f"aviso: não consegui remover regras VPN automaticamente: {e}")

    for item in normal_share_rules(wan_if, lan_if):
        changed, status = iptables_add_once(item["table"], item["rule"])
        messages.append(f"{item['name']}: {status}")

    messages.extend(apply_normal_policy_routing(wan_if, lan_if, manual_gateway))

    return {"wan_if": wan_if, "lan_if": lan_if, "messages": messages}


def disable_normal_sharing(wan_if, lan_if):
    if not command_exists("iptables"):
        raise RuntimeError("iptables não encontrado.")

    wan_if = validate_iface(wan_if)
    lan_if = validate_iface(lan_if)
    messages = []

    for item in reversed(normal_share_rules(wan_if, lan_if)):
        removed, err = iptables_delete_all(item["table"], item["rule"])
        if err:
            messages.append(f"{item['name']}: erro {err}")
        else:
            messages.append(f"{item['name']}: removidas {removed}")

    messages.extend(remove_normal_policy_routing(lan_if))

    return {"wan_if": wan_if, "lan_if": lan_if, "messages": messages}


def get_normal_sharing_status(wan_if=None, lan_if=None, manual_gateway=None):
    wan_if = (wan_if or DEFAULT_NORMAL_WAN_IF or "").strip()
    lan_if = (lan_if or DEFAULT_NORMAL_LAN_IF or "").strip()
    manual_gateway = (manual_gateway if manual_gateway is not None else DEFAULT_NORMAL_GATEWAY).strip()
    status = {
        "wan_if": wan_if,
        "lan_if": lan_if,
        "ip_forward": get_ip_forward_value(),
        "rules": [],
        "policy_rules": [],
        "route_table": [],
        "ok": False,
        "missing_wan": not bool(wan_if),
        "missing_lan": not bool(lan_if),
        "default_route": get_default_route(),
        "manual_gateway": manual_gateway,
        "gateway": None,
        "gateway_error": "",
        "wan_ipv4": [],
        "wan_ipv6": [],
        "wan_state": "unknown",
        "lan_cidrs": [],
    }

    if not wan_if or not lan_if:
        return status

    try:
        status["wan_ipv4"] = get_iface_ipv4_addresses(wan_if)
        status["wan_ipv6"] = get_iface_ipv6_addresses(wan_if)
        status["wan_state"] = get_iface_state(wan_if)
        status["lan_cidrs"] = get_iface_ipv4_cidrs(lan_if)
        try:
            status["gateway"] = get_default_gateway_for_iface(wan_if, manual_gateway)
        except Exception as gw_err:
            status["gateway_error"] = str(gw_err)

        for item in normal_share_rules(wan_if, lan_if):
            exists = iptables_rule_exists(item["table"], item["rule"]) if command_exists("iptables") else False
            status["rules"].append({"name": item["name"], "exists": exists})

        cidrs = get_iface_ipv4_cidrs(lan_if)
        for cidr in cidrs:
            parts = normal_policy_rule_parts(cidr)
            status["policy_rules"].append({"name": f"from {cidr} table {NORMAL_ROUTE_TABLE}", "exists": ip_rule_exists(parts)})

        rc, out, _ = run_cmd(["ip", "route", "show", "table", str(NORMAL_ROUTE_TABLE)], timeout=5)
        if rc == 0 and out:
            status["route_table"] = out.splitlines()

        rules_ok = all(r["exists"] for r in status["rules"])
        policy_ok = bool(status["policy_rules"]) and all(r["exists"] for r in status["policy_rules"])
        route_ok = bool(status["route_table"])
        wan_ok = bool(status["wan_ipv4"]) and status.get("gateway") is not None
        status["ok"] = status["ip_forward"] == "1" and rules_ok and policy_ok and route_ok and wan_ok
    except Exception as e:
        status["error"] = str(e)

    return status



# ==========================================================
# DIAGNOSTICO GERAL DE REDE / FIREWALL
# ==========================================================


def short_output(text, max_chars=12000):
    text = text or ""
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n... [saida cortada] ..."


def run_diag_cmd(label, args, timeout=8, max_chars=12000):
    rc, out, err = run_cmd(args, timeout=timeout)
    body = out or err or ""
    return {
        "label": label,
        "cmd": " ".join(args),
        "rc": rc,
        "ok": rc == 0,
        "output": short_output(body if body else "sem saida", max_chars=max_chars),
    }


def read_file_head(path, label, max_chars=6000):
    try:
        data = Path(path).read_text(encoding="utf-8", errors="ignore")
        return {
            "label": label,
            "cmd": f"cat {path}",
            "rc": 0,
            "ok": True,
            "output": short_output(data, max_chars=max_chars),
        }
    except Exception as e:
        return {
            "label": label,
            "cmd": f"cat {path}",
            "rc": 1,
            "ok": False,
            "output": str(e),
        }


def first_lan_test_ip(lan_if):
    try:
        cidrs = get_iface_ipv4_cidrs(lan_if)
        if not cidrs:
            return ""
        net = ipaddress.ip_network(cidrs[0], strict=False)
        # Usa um IP provável de cliente dentro da LAN. Evita network/broadcast.
        candidate = net.network_address + 10
        if candidate in net and candidate != net.network_address and candidate != net.broadcast_address:
            return str(candidate)
        for host in net.hosts():
            return str(host)
    except Exception:
        return ""
    return ""


def get_network_diagnostics(wan_if=None, lan_if=None, vpn_if=None, manual_gateway=None):
    wan_if = (wan_if or DEFAULT_NORMAL_WAN_IF or "").strip()
    lan_if = (lan_if or DEFAULT_NORMAL_LAN_IF or DEFAULT_SHARE_LAN_IF or "").strip()
    vpn_if_input = (vpn_if or DEFAULT_SHARE_VPN_IF or "auto").strip()
    manual_gateway = (manual_gateway if manual_gateway is not None else DEFAULT_NORMAL_GATEWAY).strip()

    try:
        vpn_if_detected = detect_vpn_iface(vpn_if_input)
    except Exception:
        vpn_if_detected = vpn_if_input or "auto"

    diag = {
        "wan_if": wan_if,
        "lan_if": lan_if,
        "vpn_if": vpn_if_detected,
        "manual_gateway": manual_gateway,
        "ip_forward": get_ip_forward_value(),
        "default_route": get_default_route(),
        "wan_ipv4": get_iface_ipv4_addresses(wan_if) if wan_if else [],
        "wan_ipv6": get_iface_ipv6_addresses(wan_if) if wan_if else [],
        "lan_cidrs": get_iface_ipv4_cidrs(lan_if) if lan_if else [],
        "wan_state": get_iface_state(wan_if) if wan_if else "missing",
        "lan_state": get_iface_state(lan_if) if lan_if else "missing",
        "vpn_state": get_iface_state(vpn_if_detected) if vpn_if_detected and vpn_if_detected != "auto" else "unknown",
        "gateway": None,
        "gateway_error": "",
        "commands": [],
        "tests": [],
    }

    if wan_if:
        try:
            diag["gateway"] = get_default_gateway_for_iface(wan_if, manual_gateway)
        except Exception as e:
            diag["gateway_error"] = str(e)

    # Testes leves de rota/conectividade. Nao alteram o sistema.
    diag["tests"].append(run_diag_cmd("Rota do servidor para 8.8.8.8", ["ip", "route", "get", "8.8.8.8"], timeout=5, max_chars=3000))

    lan_test_ip = first_lan_test_ip(lan_if) if lan_if else ""
    if lan_test_ip and lan_if:
        diag["tests"].append(run_diag_cmd(
            f"Rota simulando cliente {lan_test_ip} da {lan_if}",
            ["ip", "route", "get", "8.8.8.8", "from", lan_test_ip, "iif", lan_if],
            timeout=5,
            max_chars=3000,
        ))

    if command_exists("ping"):
        diag["tests"].append(run_diag_cmd("Ping IPv4 8.8.8.8", ["ping", "-4", "-c", "1", "-W", "2", "8.8.8.8"], timeout=4, max_chars=3000))
        diag["tests"].append(run_diag_cmd("Ping DNS google.com", ["ping", "-4", "-c", "1", "-W", "3", "google.com"], timeout=6, max_chars=3000))

    # Snapshots principais.
    diag["commands"].extend([
        run_diag_cmd("Interfaces - resumo", ["ip", "-br", "addr"], timeout=5),
        run_diag_cmd("Links - estado", ["ip", "-br", "link"], timeout=5),
        run_diag_cmd("Rotas IPv4 - tabela principal", ["ip", "-4", "route", "show"], timeout=5),
        run_diag_cmd("Rotas IPv6", ["ip", "-6", "route", "show"], timeout=5),
        run_diag_cmd(f"Policy rules", ["ip", "rule", "show"], timeout=5),
        run_diag_cmd(f"Tabela policy {NORMAL_ROUTE_TABLE}", ["ip", "route", "show", "table", str(NORMAL_ROUTE_TABLE)], timeout=5),
        run_diag_cmd("Firewall NAT", ["iptables", "-t", "nat", "-L", "POSTROUTING", "-n", "-v", "--line-numbers"], timeout=8),
        run_diag_cmd("Firewall FORWARD", ["iptables", "-L", "FORWARD", "-n", "-v", "--line-numbers"], timeout=8),
        run_diag_cmd("Firewall MANGLE/FORWARD", ["iptables", "-t", "mangle", "-L", "FORWARD", "-n", "-v", "--line-numbers"], timeout=8),
        run_diag_cmd("Regras NAT em formato iptables-save", ["iptables", "-t", "nat", "-S"], timeout=8),
        read_file_head("/etc/resolv.conf", "DNS /etc/resolv.conf"),
    ])

    if command_exists("nft"):
        diag["commands"].append(run_diag_cmd("nft ruleset - resumo", ["nft", "list", "ruleset"], timeout=8, max_chars=10000))

    return diag

# ==========================================================
# CONFIGS OPENVPN
# ==========================================================

def get_config_list():
    items = []
    if not OPENVPN_CONFIG_DIR.exists():
        return items
    for path in sorted(OPENVPN_CONFIG_DIR.glob("*.conf")):
        name = path.stem
        if not VALID_NAME_RE.match(name):
            continue
        state = get_unit_state(name)
        summary = parse_config_summary(path)
        try:
            st = path.stat()
            modified = datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
            size = st.st_size
        except Exception:
            modified = "-"
            size = 0
        badge = "idle"
        if state["active"] == "active":
            badge = "ok"
        elif state["active"] in {"failed", "activating", "deactivating"}:
            badge = "warn"
        items.append({
            "name": name,
            "path": str(path),
            "modified": modified,
            "size": size,
            "state": state,
            "summary": summary,
            "badge": badge,
        })
    return items


def get_journal(name, lines=120):
    validate_name_or_404(name)
    unit = unit_name(name)
    rc, out, err = run_cmd(["journalctl", "-u", unit, "-n", str(lines), "--no-pager", "-o", "short-iso"], timeout=15)
    if rc != 0 and not out:
        return err or "Sem logs disponíveis."
    return out or "Sem logs disponíveis."


def preflight_warnings():
    warnings = []
    if os.geteuid() != 0:
        warnings.append("O painel não está rodando como root. Start/stop do OpenVPN e iptables podem falhar.")
    if PANEL_PASSWORD == DEFAULT_PASSWORD:
        warnings.append("Senha padrão em uso. Defina OPENVPN_PANEL_PASSWORD antes de expor o painel na rede.")
    if not Path("/run/systemd/system").exists():
        warnings.append("systemd não parece estar ativo. O modo openvpn-client@NOME.service pode não funcionar.")
    if not command_exists("iptables"):
        warnings.append("iptables não encontrado. Instale: sudo apt install iptables")
    return warnings


# ==========================================================
# UPLOAD
# ==========================================================

def save_regular_upload(files, custom_name):
    files = [f for f in files if f and f.filename]
    if not files:
        raise ValueError("Nenhum arquivo enviado.")
    for f in files:
        if not is_allowed_file(f.filename):
            raise ValueError(f"Extensão não permitida: {f.filename}")
    configs = [f for f in files if ext_of(f.filename) in CONFIG_EXTENSIONS]
    if len(configs) != 1:
        raise ValueError("Envie exatamente um arquivo .ovpn ou .conf. Arquivos auxiliares podem ir junto.")
    cfg_file = configs[0]
    name = sanitize_config_name(custom_name or cfg_file.filename)
    target_cfg = config_path(name)
    backup_file(target_cfg)
    data = cfg_file.read()
    if not data:
        raise ValueError("Arquivo de configuração vazio.")
    target_cfg.write_bytes(data)
    os.chmod(target_cfg, 0o600)
    support_count = 0
    for f in files:
        if f is cfg_file:
            continue
        safe = secure_filename(f.filename)
        if not safe:
            continue
        if ext_of(safe) not in SUPPORT_EXTENSIONS:
            continue
        dest = OPENVPN_CONFIG_DIR / safe
        backup_file(dest)
        dest.write_bytes(f.read())
        os.chmod(dest, 0o600)
        support_count += 1
    return name, support_count


def clean_zip_member_path(member_name):
    pure = PurePosixPath(member_name)
    parts = []
    for part in pure.parts:
        if part in {"", ".", ".."}:
            continue
        safe = secure_filename(part)
        if safe:
            parts.append(safe)
    if not parts:
        return None
    return Path(*parts)


def save_zip_upload(zip_file, custom_name):
    if ext_of(zip_file.filename) not in ZIP_EXTENSIONS:
        raise ValueError("Arquivo ZIP inválido.")
    with zipfile.ZipFile(zip_file.stream) as zf:
        infos = [i for i in zf.infolist() if not i.is_dir()]
        valid_infos = []
        for info in infos:
            ext = ext_of(info.filename)
            if ext in ALLOWED_EXTENSIONS and ext not in ZIP_EXTENSIONS:
                valid_infos.append(info)
        configs = [i for i in valid_infos if ext_of(i.filename) in CONFIG_EXTENSIONS]
        if not configs:
            raise ValueError("O ZIP precisa conter pelo menos um arquivo .ovpn ou .conf.")
        main_config = sorted(configs, key=lambda x: x.filename)[0]
        name = sanitize_config_name(custom_name or main_config.filename)
        target_cfg = config_path(name)
        backup_file(target_cfg)
        cfg_data = zf.read(main_config)
        if not cfg_data:
            raise ValueError("Configuração dentro do ZIP está vazia.")
        target_cfg.write_bytes(cfg_data)
        os.chmod(target_cfg, 0o600)
        support_count = 0
        for info in valid_infos:
            if info.filename == main_config.filename:
                continue
            ext = ext_of(info.filename)
            if ext in CONFIG_EXTENSIONS:
                continue
            rel = clean_zip_member_path(info.filename)
            if not rel:
                continue
            dest = OPENVPN_CONFIG_DIR / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            backup_file(dest)
            dest.write_bytes(zf.read(info))
            os.chmod(dest, 0o600)
            support_count += 1
    return name, support_count


def save_uploaded_config(files, custom_name):
    files = [f for f in files if f and f.filename]
    if not files:
        raise ValueError("Nenhum arquivo enviado.")
    zip_files = [f for f in files if ext_of(f.filename) in ZIP_EXTENSIONS]
    if zip_files:
        if len(files) != 1:
            raise ValueError("Quando usar ZIP, envie somente o arquivo ZIP.")
        return save_zip_upload(zip_files[0], custom_name)
    return save_regular_upload(files, custom_name)


LOGIN_HTML = """
<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><title>{{ app_name }} - Login</title><meta name="viewport" content="width=device-width, initial-scale=1"><style>
body{margin:0;font-family:Arial,sans-serif;background:#0b1020;color:#e5e7eb;min-height:100vh;display:flex;align-items:center;justify-content:center}.box{width:92%;max-width:420px;background:#111827;border:1px solid #1f2937;border-radius:18px;padding:28px;box-shadow:0 20px 60px rgba(0,0,0,.35)}h1{margin:0 0 8px;font-size:24px}p{color:#9ca3af;margin-top:0}label{display:block;margin:14px 0 6px;color:#d1d5db;font-size:14px}input{width:100%;box-sizing:border-box;padding:12px;border-radius:10px;border:1px solid #374151;background:#030712;color:#e5e7eb;outline:none}button{width:100%;margin-top:18px;padding:12px;border:0;border-radius:10px;background:#22c55e;color:#04130a;font-weight:700;cursor:pointer}.flash{margin:12px 0;padding:10px;border-radius:10px;background:#451a1a;color:#fecaca;border:1px solid #7f1d1d}.small{font-size:12px;color:#6b7280;margin-top:18px}
</style></head><body><div class="box"><h1>{{ app_name }}</h1><p>Painel local para gerenciamento OpenVPN.</p>{% with messages = get_flashed_messages(with_categories=true) %}{% for cat, msg in messages %}<div class="flash">{{ msg }}</div>{% endfor %}{% endwith %}<form method="post"><input type="hidden" name="csrf" value="{{ csrf_token() }}"><label>Usuário</label><input name="username" autocomplete="username" required><label>Senha</label><input name="password" type="password" autocomplete="current-password" required><button type="submit">Entrar</button></form><div class="small">Porta padrão: 5050</div></div></body></html>
"""

DASHBOARD_HTML = """
<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<title>{{ app_name }}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="20">
<style>
:root{--bg:#050816;--card:#0f172a;--line:#1f2937;--text:#e5e7eb;--muted:#9ca3af;--green:#22c55e;--red:#ef4444;--yellow:#f59e0b;--blue:#38bdf8;--gray:#6b7280}*{box-sizing:border-box}body{margin:0;font-family:Arial,sans-serif;background:radial-gradient(circle at top left,#172554,var(--bg) 38%);color:var(--text)}header{padding:22px;border-bottom:1px solid var(--line);background:rgba(15,23,42,.85);position:sticky;top:0;z-index:20;backdrop-filter:blur(14px)}.wrap{width:min(1280px,94vw);margin:0 auto}.top{display:flex;justify-content:space-between;gap:14px;align-items:center;flex-wrap:wrap}h1{margin:0;font-size:24px}.subtitle{color:var(--muted);font-size:13px;margin-top:4px}a{color:var(--blue);text-decoration:none}.grid{display:grid;grid-template-columns:1fr;gap:18px;padding:22px 0}.card{background:rgba(15,23,42,.92);border:1px solid var(--line);border-radius:18px;padding:18px;box-shadow:0 18px 55px rgba(0,0,0,.28)}.card h2{font-size:18px;margin:0 0 14px}.flash{margin:10px 0;padding:12px;border-radius:12px;border:1px solid #334155;background:#111827;color:#d1d5db}.flash.err{background:#451a1a;color:#fecaca;border-color:#7f1d1d}.flash.ok{background:#052e16;color:#bbf7d0;border-color:#166534}.warnbox{padding:12px;border-radius:12px;background:#422006;border:1px solid #92400e;color:#fde68a;margin-bottom:10px}form.inline{display:inline}input[type=text],input[type=file],select{width:100%;padding:12px;border-radius:10px;border:1px solid #334155;background:#020617;color:var(--text);margin:6px 0 12px}label{color:#d1d5db;font-size:13px;display:block;margin-top:8px}button,.btn{border:0;padding:8px 10px;border-radius:10px;font-weight:700;cursor:pointer;display:inline-block;margin:2px;color:#04130a;background:#e5e7eb;font-size:13px}.btn-green{background:var(--green)}.btn-red{background:var(--red);color:white}.btn-yellow{background:var(--yellow)}.btn-blue{background:var(--blue)}.btn-gray{background:#374151;color:#e5e7eb}.btn-small{padding:6px 8px;font-size:12px}.tablewrap td{background-clip:padding-box}.tablewrap td:last-child{min-width:260px}.tablewrap td:nth-child(7){max-width:320px;word-break:break-word}.tablewrap td:nth-child(2),.tablewrap td:nth-child(3){word-break:break-word}table{width:100%;border-collapse:collapse;overflow:hidden;border-radius:14px;table-layout:auto}th,td{padding:10px;border-bottom:1px solid var(--line);vertical-align:top;text-align:left;font-size:13px}th{color:#cbd5e1;background:#111827;position:static;top:auto;z-index:auto}tr:hover td{background:rgba(30,41,59,.45)}.tablewrap{overflow-x:auto;overflow-y:visible;border:1px solid var(--line);border-radius:14px;position:relative;z-index:1}.badge{display:inline-flex;align-items:center;gap:6px;padding:5px 8px;border-radius:999px;font-weight:700;font-size:12px;border:1px solid #334155}.badge:before{content:"";width:8px;height:8px;border-radius:50%;background:var(--gray)}.badge.ok{background:#052e16;color:#bbf7d0;border-color:#166534}.badge.ok:before{background:var(--green)}.badge.warn{background:#422006;color:#fde68a;border-color:#92400e}.badge.warn:before{background:var(--yellow)}.badge.idle{background:#111827;color:#d1d5db}.muted{color:var(--muted);font-size:12px}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px}.two{display:grid;grid-template-columns:1fr 1fr;gap:18px}.three{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px}pre{white-space:pre-wrap;word-break:break-word;background:#020617;border:1px solid #1f2937;border-radius:14px;padding:14px;overflow:auto;max-height:520px}.oktext{color:#86efac}.badtext{color:#fca5a5}.warntext{color:#fbbf24}.diagbox{margin-top:10px}.diagbox summary{cursor:pointer;color:#cbd5e1;font-weight:700;padding:8px 0}.diag-ok{color:#86efac}.diag-bad{color:#fca5a5}.diag-mini{display:inline-block;padding:3px 7px;border-radius:999px;background:#111827;border:1px solid #334155;margin:2px}.pre-small{max-height:260px;font-size:11px}@media(max-width:900px){.two,.three{grid-template-columns:1fr}th,td{font-size:12px;padding:8px}header{position:relative}th{position:static}}
</style>
</head>
<body>
<header><div class="wrap top"><div><h1>{{ app_name }}</h1><div class="subtitle">Host: {{ host }} · Porta: {{ port }} · Config dir: <span class="mono">{{ config_dir }}</span></div></div><div><a class="btn btn-gray" href="{{ url_for('api_status') }}">API JSON</a><a class="btn btn-red" href="{{ url_for('logout') }}">Sair</a></div></div></header>
<main class="wrap grid">
{% with messages = get_flashed_messages(with_categories=true) %}{% for cat, msg in messages %}<div class="flash {{ cat }}">{{ msg }}</div>{% endfor %}{% endwith %}
{% for w in warnings %}<div class="warnbox">{{ w }}</div>{% endfor %}

<section class="card">
<h2>Compartilhamento de internet através da VPN</h2>
<div class="three">
  <div>
    <div class="muted">Status geral</div>
    {% if sharing.ok %}<p class="oktext"><strong>ATIVO</strong> — clientes da interface LAN saem pela VPN.</p>{% else %}<p class="warntext"><strong>NÃO ATIVO</strong> — falta ip_forward, interface LAN ou regras iptables.</p>{% endif %}
    <p class="muted">IPv4 forward: <span class="mono">{{ sharing.ip_forward }}</span></p>
    <p class="muted">Rota default atual: <span class="mono">{{ sharing.default_route }}</span></p>
  </div>
  <div>
    <div class="muted">Regras esperadas</div>
    {% if sharing.missing_lan %}<p class="warntext">Informe a interface LAN que entrega internet aos clientes.</p>{% endif %}
    <ul>
    {% for r in sharing.rules %}
      <li>{% if r.exists %}<span class="oktext">OK</span>{% else %}<span class="badtext">FALTA</span>{% endif %} — {{ r.name }}</li>
    {% endfor %}
    </ul>
  </div>
  <div>
    <div class="muted">Interfaces detectadas</div>
    <p class="muted">VPN usada: <span class="mono">{{ sharing.vpn_if }}</span></p>
    <p class="muted">Interfaces: <span class="mono">{{ all_interfaces|join(', ') }}</span></p>
  </div>
</div>

<form method="post" action="{{ url_for('share_action') }}">
  <input type="hidden" name="csrf" value="{{ csrf_token() }}">
  <div class="three">
    <div>
      <label>Interface LAN que entrega internet aos clientes</label>
      <input type="text" name="lan_if" value="{{ default_lan_if }}" placeholder="ex: wlan0, eth1, br0, ap0" required>
    </div>
    <div>
      <label>Interface VPN de saída</label>
      <input type="text" name="vpn_if" value="{{ default_vpn_if }}" placeholder="auto ou tun0">
    </div>
    <div>
      <label>Ação</label>
      <button class="btn-green" name="action" value="enable">Ativar compartilhamento pela VPN</button>
      <button class="btn-red" name="action" value="disable">Desativar regras VPN</button>
      <button class="btn-blue" name="action" value="save">Salvar regras no boot</button>
    </div>
  </div>
  <div class="muted">Use aqui a interface onde estão conectados os clientes. Se seu Linux recebe internet por eth0/end0 e compartilha por wlan0, coloque wlan0.</div>
</form>
</section>

<section class="card">
<h2>Voltar para internet normal sem VPN</h2>
<div class="three">
  <div>
    <div class="muted">Status normal</div>
    {% if normal_sharing.ok %}<p class="oktext"><strong>ATIVO</strong> — clientes saem pela internet normal.</p>{% else %}<p class="warntext"><strong>NÃO ATIVO</strong> — modo normal ainda não está aplicado ou falta policy route.</p>{% endif %}
    <p class="muted">WAN normal: <span class="mono">{{ normal_sharing.wan_if }}</span> · estado: <span class="mono">{{ normal_sharing.wan_state }}</span></p>
    <p class="muted">WAN IPv4: <span class="mono">{{ normal_sharing.wan_ipv4|join(', ') if normal_sharing.wan_ipv4 else 'SEM IPv4' }}</span></p>
    <p class="muted">WAN IPv6: <span class="mono">{{ normal_sharing.wan_ipv6|join(', ') if normal_sharing.wan_ipv6 else 'sem IPv6' }}</span></p>
    <p class="muted">Gateway normal: <span class="mono">{{ normal_sharing.gateway if normal_sharing.gateway is not none else 'não detectado' }}</span></p>
    {% if normal_sharing.gateway_error %}<p class="badtext">{{ normal_sharing.gateway_error }}</p>{% endif %}
    <p class="muted">LAN/clientes: <span class="mono">{{ normal_sharing.lan_if }}</span></p>
    <p class="muted">Tabela policy route: <span class="mono">{{ normal_route_table }}</span></p>
  </div>
  <div>
    <div class="muted">Regras NAT normais</div>
    {% if normal_sharing.missing_wan %}<p class="warntext">Informe a interface que recebe internet normal, exemplo end0.</p>{% endif %}
    {% if normal_sharing.missing_lan %}<p class="warntext">Informe a interface que entrega internet aos clientes, exemplo wlan0.</p>{% endif %}
    <ul>
    {% for r in normal_sharing.rules %}
      <li>{% if r.exists %}<span class="oktext">OK</span>{% else %}<span class="badtext">FALTA</span>{% endif %} — {{ r.name }}</li>
    {% endfor %}
    </ul>
  </div>
  <div>
    <div class="muted">Policy route para ignorar redirect-gateway da VPN</div>
    <ul>
    {% for r in normal_sharing.policy_rules %}
      <li>{% if r.exists %}<span class="oktext">OK</span>{% else %}<span class="badtext">FALTA</span>{% endif %} — {{ r.name }}</li>
    {% endfor %}
    </ul>
    {% if normal_sharing.route_table %}<pre>{% for r in normal_sharing.route_table %}{{ r }}
{% endfor %}</pre>{% endif %}
  </div>
</div>

<form method="post" action="{{ url_for('share_action') }}">
  <input type="hidden" name="csrf" value="{{ csrf_token() }}">
  <div class="three">
    <div>
      <label>Interface que recebe internet normal / WAN</label>
      <input type="text" name="normal_wan_if" value="{{ default_normal_wan_if }}" placeholder="ex: end0, eth0, wlan0" required>
      <label>Gateway IPv4 normal opcional</label>
      <input type="text" name="normal_gateway" value="{{ default_normal_gateway }}" placeholder="ex: 192.168.1.1 ou vazio para automático">
    </div>
    <div>
      <label>Interface que entrega internet aos clientes / LAN</label>
      <input type="text" name="normal_lan_if" value="{{ default_normal_lan_if }}" placeholder="ex: wlan0, end0, br0" required>
    </div>
    <div>
      <label>Ação</label>
      <button class="btn-yellow" name="action" value="normal">Voltar internet normal</button>
      <button class="btn-blue" name="action" value="wan_dhcp">Renovar IPv4 DHCP da WAN</button>
      <button class="btn-blue" name="action" value="normal_reverse">Inverter WAN/LAN</button>
      <button class="btn-red" name="action" value="normal_disable">Remover regras normais</button>
      <button class="btn-gray" name="action" value="save">Salvar regras no boot</button>
    </div>
  </div>
  <div class="muted">Exemplo principal: internet entra por <span class="mono">end0</span> e sai para clientes por <span class="mono">wlan0</span>. Se quiser o contrário, use Inverter WAN/LAN.</div>
</form>
</section>

<section class="two">
<div class="card"><h2>Enviar configuração OpenVPN</h2><form method="post" action="{{ url_for('upload') }}" enctype="multipart/form-data"><input type="hidden" name="csrf" value="{{ csrf_token() }}"><label>Nome opcional da conexão</label><input type="text" name="name" placeholder="exemplo: cliente_empresa"><label>Arquivos</label><input type="file" name="files" multiple required><div class="muted">Aceita .ovpn, .conf e arquivos auxiliares .crt, .key, .pem, .p12, .auth, .txt. Também aceita .zip com uma configuração.</div><br><button class="btn-green" type="submit">Enviar configuração</button></form></div>
<div class="card"><h2>Status de rede VPN</h2><div class="muted">Interfaces VPN detectadas:</div>{% if interfaces %}<ul>{% for i in interfaces %}<li><span class="mono">{{ i.iface }}</span> · {{ i.family }} · <span class="mono">{{ i.address }}</span></li>{% endfor %}</ul>{% else %}<p class="muted">Nenhuma interface tun/tap/ovpn ativa detectada.</p>{% endif %}<div class="muted">Rotas passando por VPN:</div>{% if routes %}<pre>{% for r in routes %}{{ r }}
{% endfor %}</pre>{% else %}<p class="muted">Nenhuma rota VPN detectada.</p>{% endif %}</div>
</section>

<section class="card">
<h2>Conexões OpenVPN</h2>
{% if configs %}
<div class="tablewrap"><table><thead><tr><th>Status</th><th>Nome</th><th>Servidor remoto</th><th>Dev/Proto</th><th>Boot</th><th>PID</th><th>Arquivo</th><th>Ações</th></tr></thead><tbody>
{% for c in configs %}
<tr><td><span class="badge {{ c.badge }}">{{ c.state.active }}</span><div class="muted">{{ c.state.sub_state }}</div>{% if c.summary.auth_warning %}<div class="muted" style="color:#fbbf24;">auth-user-pass sem arquivo. Pode travar pedindo usuário/senha.</div>{% endif %}</td><td><strong>{{ c.name }}</strong><div class="muted mono">{{ c.state.unit }}</div></td><td class="mono">{{ c.summary.remote }}</td><td><span class="mono">{{ c.summary.dev }}</span> / <span class="mono">{{ c.summary.proto }}</span></td><td><span class="mono">{{ c.state.enabled }}</span></td><td class="mono">{{ c.state.main_pid }}</td><td><span class="mono">{{ c.path }}</span><div class="muted">{{ c.size }} bytes · {{ c.modified }}</div></td><td>
<form class="inline" method="post" action="{{ url_for('config_action', name=c.name, cmd='start') }}"><input type="hidden" name="csrf" value="{{ csrf_token() }}"><button class="btn-green btn-small">Conectar</button></form>
<form class="inline" method="post" action="{{ url_for('config_action', name=c.name, cmd='stop') }}"><input type="hidden" name="csrf" value="{{ csrf_token() }}"><button class="btn-red btn-small">Desconectar</button></form>
<form class="inline" method="post" action="{{ url_for('config_action', name=c.name, cmd='restart') }}"><input type="hidden" name="csrf" value="{{ csrf_token() }}"><button class="btn-yellow btn-small">Reiniciar</button></form><br>
<form class="inline" method="post" action="{{ url_for('config_action', name=c.name, cmd='enable') }}"><input type="hidden" name="csrf" value="{{ csrf_token() }}"><button class="btn-blue btn-small">Habilitar boot</button></form>
<form class="inline" method="post" action="{{ url_for('config_action', name=c.name, cmd='disable') }}"><input type="hidden" name="csrf" value="{{ csrf_token() }}"><button class="btn-gray btn-small">Desabilitar boot</button></form><br>
<form class="inline" method="post" action="{{ url_for('config_action', name=c.name, cmd='reset_failed') }}"><input type="hidden" name="csrf" value="{{ csrf_token() }}"><button class="btn-gray btn-small">Limpar falha</button></form>
<a class="btn btn-gray btn-small" href="{{ url_for('logs', name=c.name) }}">Logs</a><a class="btn btn-gray btn-small" href="{{ url_for('download_config', name=c.name) }}">Baixar</a>
<form class="inline" method="post" action="{{ url_for('config_action', name=c.name, cmd='delete') }}" onsubmit="return confirm('Remover esta configuração? A conexão será parada antes.');"><input type="hidden" name="csrf" value="{{ csrf_token() }}"><button class="btn-red btn-small">Remover</button></form>
</td></tr>
{% endfor %}
</tbody></table></div>
{% else %}<p class="muted">Nenhuma configuração encontrada em {{ config_dir }}.</p>{% endif %}
</section>


<section class="card">
<h2>Status completo da rede, rotas e firewall</h2>
<div class="three">
  <div>
    <div class="muted">Resumo das interfaces</div>
    <p>WAN: <span class="mono">{{ network_diag.wan_if }}</span> — estado <span class="mono">{{ network_diag.wan_state }}</span></p>
    <p>LAN/clientes: <span class="mono">{{ network_diag.lan_if }}</span> — estado <span class="mono">{{ network_diag.lan_state }}</span></p>
    <p>VPN detectada: <span class="mono">{{ network_diag.vpn_if }}</span> — estado <span class="mono">{{ network_diag.vpn_state }}</span></p>
    <p>IPv4 forward: <span class="mono">{{ network_diag.ip_forward }}</span></p>
  </div>
  <div>
    <div class="muted">Endereços e gateway</div>
    <p>WAN IPv4: <span class="mono">{{ network_diag.wan_ipv4|join(', ') if network_diag.wan_ipv4 else 'SEM IPv4' }}</span></p>
    <p>WAN IPv6: <span class="mono">{{ network_diag.wan_ipv6|join(', ') if network_diag.wan_ipv6 else '-' }}</span></p>
    <p>LAN CIDR: <span class="mono">{{ network_diag.lan_cidrs|join(', ') if network_diag.lan_cidrs else '-' }}</span></p>
    <p>Gateway normal: <span class="mono">{{ network_diag.gateway if network_diag.gateway is not none else '-' }}</span></p>
    {% if network_diag.gateway_error %}<p class="badtext">{{ network_diag.gateway_error }}</p>{% endif %}
  </div>
  <div>
    <div class="muted">Rota padrão atual</div>
    <pre class="pre-small">{{ network_diag.default_route }}</pre>
    <div class="muted">Testes rápidos</div>
    {% for t in network_diag.tests %}
      <div class="diag-mini {% if t.ok %}diag-ok{% else %}diag-bad{% endif %}">{{ t.label }}: rc={{ t.rc }}</div>
    {% endfor %}
  </div>
</div>

<div class="two">
  <div>
    <h3 style="font-size:15px;margin:14px 0 8px;">Testes de rota e conectividade</h3>
    {% for t in network_diag.tests %}
      <details class="diagbox" {% if not t.ok %}open{% endif %}>
        <summary>{% if t.ok %}<span class="diag-ok">OK</span>{% else %}<span class="diag-bad">ERRO</span>{% endif %} — {{ t.label }} <span class="muted mono">rc={{ t.rc }}</span></summary>
        <div class="muted mono">{{ t.cmd }}</div>
        <pre class="pre-small">{{ t.output }}</pre>
      </details>
    {% endfor %}
  </div>
  <div>
    <h3 style="font-size:15px;margin:14px 0 8px;">Comandos de diagnóstico</h3>
    {% for c in network_diag.commands %}
      <details class="diagbox">
        <summary>{% if c.ok %}<span class="diag-ok">OK</span>{% else %}<span class="diag-bad">ERRO</span>{% endif %} — {{ c.label }} <span class="muted mono">rc={{ c.rc }}</span></summary>
        <div class="muted mono">{{ c.cmd }}</div>
        <pre class="pre-small">{{ c.output }}</pre>
      </details>
    {% endfor %}
  </div>
</div>
</section>

</main></body></html>
"""

LOGS_HTML = """
<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><title>Logs - {{ name }}</title><meta name="viewport" content="width=device-width, initial-scale=1"><meta http-equiv="refresh" content="10"><style>body{margin:0;font-family:Arial,sans-serif;background:#050816;color:#e5e7eb}.wrap{width:min(1100px,94vw);margin:0 auto;padding:22px 0}a{color:#38bdf8;text-decoration:none}pre{white-space:pre-wrap;word-break:break-word;background:#020617;border:1px solid #1f2937;border-radius:14px;padding:14px;overflow:auto}.btn{border:0;padding:8px 10px;border-radius:10px;font-weight:700;display:inline-block;margin:2px;background:#374151;color:#e5e7eb}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}</style></head><body><div class="wrap"><h1>Logs: <span class="mono">{{ name }}</span></h1><p><a class="btn" href="{{ url_for('index') }}">Voltar</a><a class="btn" href="{{ url_for('logs_raw', name=name) }}">Ver texto puro</a></p><pre>{{ logs }}</pre></div></body></html>
"""


@app.get("/health")
def health():
    return jsonify({"ok": True, "app": APP_NAME, "time": int(time.time())})


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        check_csrf()
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        ok_user = hmac.compare_digest(username, PANEL_USER)
        ok_pass = hmac.compare_digest(password, PANEL_PASSWORD)
        if ok_user and ok_pass:
            session["logged_in"] = True
            flash("Login realizado.", "ok")
            return redirect(url_for("index"))
        flash("Usuário ou senha inválidos.", "err")
    return render_template_string(LOGIN_HTML, app_name=APP_NAME)


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.get("/")
@login_required
def index():
    configs = get_config_list()
    interfaces = get_vpn_interfaces()
    routes = get_routes_summary()
    all_interfaces = get_all_interfaces()
    default_lan_if = DEFAULT_SHARE_LAN_IF or ("wlan0" if "wlan0" in all_interfaces else "")
    default_vpn_if = DEFAULT_SHARE_VPN_IF or "auto"
    default_normal_wan_if = DEFAULT_NORMAL_WAN_IF if DEFAULT_NORMAL_WAN_IF in all_interfaces else DEFAULT_NORMAL_WAN_IF
    default_normal_lan_if = DEFAULT_NORMAL_LAN_IF if DEFAULT_NORMAL_LAN_IF in all_interfaces else (default_lan_if or DEFAULT_NORMAL_LAN_IF)
    default_normal_gateway = DEFAULT_NORMAL_GATEWAY
    sharing = get_vpn_sharing_status(default_lan_if, default_vpn_if)
    normal_sharing = get_normal_sharing_status(default_normal_wan_if, default_normal_lan_if, default_normal_gateway)
    network_diag = get_network_diagnostics(default_normal_wan_if, default_normal_lan_if, default_vpn_if, default_normal_gateway)
    return render_template_string(
        DASHBOARD_HTML,
        app_name=APP_NAME,
        configs=configs,
        interfaces=interfaces,
        routes=routes,
        warnings=preflight_warnings(),
        config_dir=str(OPENVPN_CONFIG_DIR),
        host=HOST,
        port=PORT,
        all_interfaces=all_interfaces,
        default_lan_if=default_lan_if,
        default_vpn_if=default_vpn_if,
        default_normal_wan_if=default_normal_wan_if,
        default_normal_lan_if=default_normal_lan_if,
        default_normal_gateway=default_normal_gateway,
        normal_sharing=normal_sharing,
        normal_route_table=NORMAL_ROUTE_TABLE,
        network_diag=network_diag,
        sharing=sharing,
    )


@app.get("/api/status")
@login_required
def api_status():
    default_lan_if = DEFAULT_SHARE_LAN_IF
    default_vpn_if = DEFAULT_SHARE_VPN_IF
    return jsonify({
        "app": APP_NAME,
        "config_dir": str(OPENVPN_CONFIG_DIR),
        "configs": get_config_list(),
        "interfaces": get_vpn_interfaces(),
        "all_interfaces": get_all_interfaces(),
        "routes": get_routes_summary(),
        "default_route": get_default_route(),
        "sharing": get_vpn_sharing_status(default_lan_if, default_vpn_if),
        "normal_sharing": get_normal_sharing_status(DEFAULT_NORMAL_WAN_IF, DEFAULT_NORMAL_LAN_IF, DEFAULT_NORMAL_GATEWAY),
        "network_diag": get_network_diagnostics(DEFAULT_NORMAL_WAN_IF, DEFAULT_NORMAL_LAN_IF, DEFAULT_SHARE_VPN_IF, DEFAULT_NORMAL_GATEWAY),
        "normal_route_table": NORMAL_ROUTE_TABLE,
        "warnings": preflight_warnings(),
    })


@app.post("/share/vpn")
@login_required
def share_action():
    check_csrf()
    action = request.form.get("action", "")
    lan_if = request.form.get("lan_if", "").strip()
    vpn_if = request.form.get("vpn_if", "auto").strip() or "auto"
    normal_wan_if = request.form.get("normal_wan_if", "").strip()
    normal_lan_if = request.form.get("normal_lan_if", "").strip()
    normal_gateway = request.form.get("normal_gateway", "").strip()

    try:
        if action == "enable":
            result = apply_vpn_sharing(lan_if, vpn_if)
            flash(f"Compartilhamento VPN ativado: LAN {result['lan_if']} -> VPN {result['vpn_if']}. " + " | ".join(result["messages"]), "ok")

        elif action == "disable":
            result = disable_vpn_sharing(lan_if, vpn_if)
            flash(f"Regras de compartilhamento VPN removidas: LAN {result['lan_if']} -> VPN {result['vpn_if']}. " + " | ".join(result["messages"]), "ok")

        elif action == "normal":
            result = apply_normal_sharing(normal_wan_if, normal_lan_if, remove_vpn=True, manual_gateway=normal_gateway)
            flash(f"Internet normal restaurada: WAN {result['wan_if']} -> LAN {result['lan_if']}. " + " | ".join(result["messages"]), "ok")

        elif action == "normal_reverse":
            result = apply_normal_sharing(normal_lan_if, normal_wan_if, remove_vpn=True, manual_gateway=normal_gateway)
            flash(f"Internet normal invertida: WAN {result['wan_if']} -> LAN {result['lan_if']}. " + " | ".join(result["messages"]), "ok")

        elif action == "wan_dhcp":
            messages = renew_wan_ipv4(normal_wan_if)
            flash(f"Renovação DHCP IPv4 executada na WAN {normal_wan_if}. " + " | ".join(messages), "ok")

        elif action == "normal_disable":
            result = disable_normal_sharing(normal_wan_if, normal_lan_if)
            flash(f"Regras normais removidas: WAN {result['wan_if']} -> LAN {result['lan_if']}. " + " | ".join(result["messages"]), "ok")

        elif action == "save":
            msg = save_firewall_rules()
            flash(msg, "ok")

        else:
            flash("Ação inválida.", "err")
    except Exception as e:
        flash(str(e), "err")
    return redirect(url_for("index"))


@app.post("/upload")
@login_required
def upload():
    check_csrf()
    try:
        files = request.files.getlist("files")
        custom_name = request.form.get("name", "").strip()
        name, support_count = save_uploaded_config(files, custom_name)
        flash(f"Configuração '{name}' enviada com sucesso. Arquivos auxiliares salvos: {support_count}.", "ok")
    except Exception as e:
        flash(str(e), "err")
    return redirect(url_for("index"))


@app.post("/config/<name>/<cmd>")
@login_required
def config_action(name, cmd):
    check_csrf()
    validate_name_or_404(name)
    path = config_path(name)
    unit = unit_name(name)
    if cmd not in {"start", "stop", "restart", "enable", "disable", "reset_failed", "delete"}:
        abort(404)
    if cmd != "delete" and not path.exists():
        flash(f"Configuração não encontrada: {name}", "err")
        return redirect(url_for("index"))

    if cmd == "start":
        rc, out, err = run_cmd(["systemctl", "start", unit], timeout=30)
        if rc == 0 and AUTO_SHARE_ON_START and DEFAULT_SHARE_LAN_IF:
            try:
                result = apply_vpn_sharing(DEFAULT_SHARE_LAN_IF, DEFAULT_SHARE_VPN_IF)
                out = (out + "\n" if out else "") + f"NAT VPN aplicado: {result['lan_if']} -> {result['vpn_if']}"
            except Exception as e:
                err = (err + "\n" if err else "") + f"VPN conectou, mas falhou ao aplicar NAT: {e}"

    elif cmd == "stop":
        rc, out, err = run_cmd(["systemctl", "stop", unit], timeout=30)

    elif cmd == "restart":
        rc, out, err = run_cmd(["systemctl", "restart", unit], timeout=30)
        if rc == 0 and AUTO_SHARE_ON_START and DEFAULT_SHARE_LAN_IF:
            try:
                result = apply_vpn_sharing(DEFAULT_SHARE_LAN_IF, DEFAULT_SHARE_VPN_IF)
                out = (out + "\n" if out else "") + f"NAT VPN aplicado: {result['lan_if']} -> {result['vpn_if']}"
            except Exception as e:
                err = (err + "\n" if err else "") + f"VPN reiniciou, mas falhou ao aplicar NAT: {e}"

    elif cmd == "enable":
        rc, out, err = run_cmd(["systemctl", "enable", unit], timeout=30)

    elif cmd == "disable":
        rc, out, err = run_cmd(["systemctl", "disable", unit], timeout=30)

    elif cmd == "reset_failed":
        rc, out, err = run_cmd(["systemctl", "reset-failed", unit], timeout=15)

    elif cmd == "delete":
        run_cmd(["systemctl", "stop", unit], timeout=30)
        run_cmd(["systemctl", "disable", unit], timeout=30)
        if path.exists():
            backup = backup_file(path)
            path.unlink()
            flash(f"Configuração '{name}' removida. Backup: {backup}", "ok")
        else:
            flash(f"Configuração '{name}' não existe.", "err")
        return redirect(url_for("index"))

    msg = out or err or f"Comando executado: {cmd}"
    if rc == 0:
        flash(f"{name}: {cmd} OK. {msg}", "ok")
    else:
        flash(f"{name}: erro ao executar {cmd}. {msg}", "err")
    return redirect(url_for("index"))


@app.get("/config/<name>/logs")
@login_required
def logs(name):
    validate_name_or_404(name)
    return render_template_string(LOGS_HTML, name=name, logs=get_journal(name, lines=160))


@app.get("/config/<name>/logs/raw")
@login_required
def logs_raw(name):
    validate_name_or_404(name)
    return get_journal(name, lines=200), 200, {"Content-Type": "text/plain; charset=utf-8"}


@app.get("/config/<name>/download")
@login_required
def download_config(name):
    validate_name_or_404(name)
    path = config_path(name)
    if not path.exists():
        abort(404)
    return send_file(path, as_attachment=True, download_name=f"{name}.conf", mimetype="text/plain")


if __name__ == "__main__":
    ensure_directories()
    print(f"{APP_NAME} iniciado.")
    print(f"URL: http://{HOST}:{PORT}")
    print(f"Usuário: {PANEL_USER}")
    print(f"LAN compartilhada padrão VPN: {DEFAULT_SHARE_LAN_IF or 'não definida'}")
    print(f"VPN padrão: {DEFAULT_SHARE_VPN_IF}")
    print(f"Auto NAT ao conectar: {AUTO_SHARE_ON_START}")
    print(f"WAN normal padrão: {DEFAULT_NORMAL_WAN_IF}")
    print(f"LAN normal padrão: {DEFAULT_NORMAL_LAN_IF}")
    print(f"Gateway normal padrão: {DEFAULT_NORMAL_GATEWAY or 'auto'}")
    print(f"Tabela policy route normal: {NORMAL_ROUTE_TABLE}")
    if PANEL_PASSWORD == DEFAULT_PASSWORD:
        print("ATENÇÃO: senha padrão em uso: admin123")
    app.run(host=HOST, port=PORT, debug=False, threaded=True)
