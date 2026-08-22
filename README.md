# Upstream Healer

Automatic recovery for Nginx Proxy Manager upstreams when backend IPs change.

Designed for a Raspberry Pi running Debian 12 + Nginx Proxy Manager.

## Features (v1)

- Monitors one or more backend hosts by **MAC address**
- Configurable **grace period** (default 10 min) so maintenance/reboots don’t trigger false alerts
- When a host stays down past the grace period:
  1. Alerts you
  2. Scans the LAN for the device’s new IP
  3. Updates the corresponding NPM proxy host
  4. Performs a **graceful** `nginx -s reload` (other sites stay up)
- Notifications: **Telegram** (multiple people) + **Email** (Dynu / Gmail / any SMTP)
- Per-event toggles so you can silence noisy levels
- Clean modern web UI
- Easy to extend later

## Requirements

- Docker + Docker Compose on the Raspberry Pi
- The NPM container must be named `nginx-app-1` (or change it in `app/config.py`)
- The healer needs access to the Docker socket and the LAN (`network_mode: host`)

## Quick Start

```bash
# On the Raspberry Pi
cd /path/to/upstream-healer

# Build and start
docker compose up -d --build

# View logs
docker compose logs -f
```

UI will be available at:

```
http://<raspberry-pi-ip>:8787
```

## First-time setup in the UI

1. **Add Telegram channel**  
   - Notifications → + Telegram  
   - Paste bot token from BotFather (`@hylla_mon_bot`)  
   - Paste the two Chat IDs (comma-separated)

2. **Add Email channel** (optional but recommended)  
   - Notifications → + Email  
   - Use your Dynu SMTP settings  
   - Add 2–3 recipient addresses

3. **Add your first host (vault)**  
   - Dashboard → Add Host  
   - Name: `vault`  
   - Domain: `vault.hylla.us`  
   - MAC address of the vault machine  
   - Current IP  
   - Select the correct NPM Proxy Host ID from the dropdown  
   - Grace period: 10 (or whatever you prefer)

4. Done. The healer will now watch it.

## How to get the MAC address

On the vault machine itself:

```bash
ip link show
# or
cat /sys/class/net/*/address
```

Or from any machine on the LAN after the device has been online:

```bash
arp -a
# or
ip neigh
```

## Safety notes

- The healer **never restarts** the NPM container.
- It only runs `nginx -s reload`, which is graceful and does not drop existing connections on the other sites.
- All configuration lives in a Docker volume (`healer-data`).

## Updating later

```bash
cd /path/to/upstream-healer
git pull          # if you keep it in git
docker compose up -d --build
```

## Future ideas (easy to add)

- More hosts
- Webhook notifications
- Slack / Discord
- Automatic test of the recovered site on multiple ports
- Read-only status page
- VPN-only access documentation

---

Built for the Hylla home lab.
