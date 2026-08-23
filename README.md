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

## Docker exec administration

The same configuration can be managed without the UI from the host running Docker. Run these commands from the project directory or any shell with access to the container. Every command prints JSON on success and an error message with a non-zero exit code on failure.

### Hosts

Add a monitored host. The MAC address is normalized automatically; `--port` defaults to `80`, `--grace-minutes` defaults to `10`, and `--ip` and `--domain` are optional.

```bash
docker exec upstream-healer python -m app.cli add-host \
   --name vault \
   --mac aa:bb:cc:dd:ee:ff \
   --ip 192.168.1.20 \
   --port 8080 \
   --domain vault.example.com \
   --npm-proxy-host-id 12 \
   --grace-minutes 10
```

`--npm-proxy-host-id` is optional. Include it to update that Nginx Proxy Manager proxy host during recovery; omit it when the healer should only monitor and report the host.

Host identity is unique by the combination of MAC address and port. The same MAC can therefore be monitored on multiple ports, but adding the same MAC/port pair twice is rejected.

List monitored hosts and their IDs, ports, current IPs, and statuses:

```bash
docker exec upstream-healer python -m app.cli list-hosts
```

Disable monitoring for a host without deleting it. Get `HOST_ID` from `list-hosts`:

```bash
docker exec upstream-healer python -m app.cli disable-host HOST_ID
```

### Events

List the 10 most recent events from the last day (the defaults):

```bash
docker exec upstream-healer python -m app.cli list-events
```

Filter by host, return up to 25 events, and search the last 7 days:

```bash
docker exec upstream-healer python -m app.cli list-events \
   --host-id HOST_ID \
   --limit 25 \
   --days 7
```

`--host-id` is optional. `--limit` and `--days` must each be at least `1`.

### Telegram notifications

Add an enabled Telegram channel. Multiple chat IDs can be supplied as a comma-separated list. All current event types are enabled automatically for the new channel.

```bash
docker exec upstream-healer python -m app.cli add-telegram \
   --name Alerts \
   --bot-token 'BOT_TOKEN' \
   --chat-ids 'CHAT_ID_1,CHAT_ID_2'
```

List Telegram channels and their IDs:

```bash
docker exec upstream-healer python -m app.cli list-telegram
```

Disable a Telegram channel without deleting it. Get `CHANNEL_ID` from `list-telegram`:

```bash
docker exec upstream-healer python -m app.cli disable-telegram CHANNEL_ID
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
