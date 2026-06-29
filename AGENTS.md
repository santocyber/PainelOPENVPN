# AGENTS.md — PainelOPENVPN

Single-file Flask app (`openVPN.py`, 1645 lines) managing OpenVPN client configs via systemd and iptables NAT.

## Run & dev

```bash
# Requires Flask (no requirements.txt)
pip install flask

# All config via env vars (see top of openVPN.py for full list)
export OPENVPN_PANEL_USER=admin
export OPENVPN_PANEL_PASSWORD=admin123
export OPENVPN_CONFIG_DIR=/etc/openvpn/client
export OPENVPN_SHARE_LAN_IF=wlan0

# Start
python3 openVPN.py
# Binds 0.0.0.0:5050 by default
```

## Architecture

- **`openVPN.py`** — single file: Flask app, HTML templates (embedded `LOGIN_HTML`, `DASHBOARD_HTML`, `LOGS_HTML`), iptables helpers, diagnostics, all in one.
- **No separate templates/static** — HTML rendered via `render_template_string`.
- **Config storage** — flat `.conf` files in `OPENVPN_CONFIG_DIR`.
- **Service control** — systemd units named `openvpn-client@<name>.service`.
- **Health check** — `GET /health` returns `{"ok": true, ...}` (no auth).

## Key quirks

| Quirk               | Detail                                                                                                                                |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| CSRF                | Custom token-based (not Flask-WTF). Token in session, matched against form field `csrf`.                                              |
| Auth                | Single user/password via env vars. Default password `admin123` — startup prints a warning.                                            |
| File upload         | Accepts `.ovpn/.conf/.crt/.key/.pem/.p12/.txt/.auth/.pass/.ca/.tlsauth` + `.zip`. Zips are extracted.                                 |
| NAT modes           | Two mutually exclusive modes: **VPN** (traffic routed through VPN) and **Normal** (traffic bypasses VPN via separate WAN/LAN ifaces). |
| Interface discovery | Auto-detects VPN interfaces by scanning for `tun`, `tap`, `ovpn` prefixed interfaces.                                                 |
| Policy routing      | Uses ip rule table 100 / priority 10010 for normal mode (configurable via env).                                                       |

## No tests / no CI / no linting

This repo has zero test files, no linter config, no formatter config, and no git history. Make no assumptions about a test runner. Any changes must be verified manually.

## Environment variables (minimum to change)

| Variable                      | Default               | Note                           |
| ----------------------------- | --------------------- | ------------------------------ |
| `OPENVPN_PANEL_PASSWORD`      | `admin123`            | Change in production           |
| `OPENVPN_PANEL_SECRET`        | random                | Flask session secret           |
| `OPENVPN_CONFIG_DIR`          | `/etc/openvpn/client` | Config file directory          |
| `OPENVPN_PANEL_HOST`          | `0.0.0.0`             | Bind address                   |
| `OPENVPN_PANEL_PORT`          | `5050`                | Bind port                      |
| `OPENVPN_SHARE_LAN_IF`        | `""`                  | LAN interface for VPN NAT      |
| `OPENVPN_AUTO_SHARE_ON_START` | `0`                   | Auto-apply NAT after VPN start |
| `OPENVPN_NORMAL_WAN_IF`       | `end0`                | WAN for normal internet        |
| `OPENVPN_NORMAL_LAN_IF`       | `wlan0`               | LAN for normal internet        |
