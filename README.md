# watchlog

**Your server, watched while you sleep.**

watchlog is a small Python tool that runs on your Linux server and quietly checks the
12 things that commonly break – SSL certificates, security updates, disk space, mail
deliverability, brute-force attacks, blacklists, and more. When something needs your
attention, you get an email and a Telegram message with a one-tap action button.
The rest of the time, it stays silent.

🌐 **Landing page:** [watchlog.pl](https://watchlog.pl) · also in [Polish](https://watchlog.pl/pl/)

## Why does this exist?

You run a server. It hosts a website, email, maybe a database. Plenty of small things
can quietly break, and you only find out when something already stopped working:

- Your **SSL certificate expires** and the green padlock turns red.
- A **critical security update** is published but nobody installs it.
- The **disk fills up** and your database can't write any more.
- A **service crashes** silently in the night.
- Someone is **hammering your SSH** with thousands of password guesses.
- Your **IP lands on a spam blacklist** and emails stop being delivered.

The classic answer is "log into the server every day and check". Nobody actually does
that. Small problems pile up until something breaks.

watchlog runs on your server, checks 12 things every 4 hours, and only contacts you
when something needs attention. You get an email and a Telegram message with a one-tap
button. Tap "Apply security updates" on your phone and the patch installs itself.
No SSH session, no logging in to check, no daily digest spam.

It's free, open source (MIT), and you keep all your data – nothing leaves your server.

## What you get

- 🔒 **Security-focused** – APT security updates flagged as critical, IP blacklist monitoring, SSH brute-force detection, file-integrity (AIDE), open-ports baseline diff
- 🤫 **No spam** – email and Telegram only when something is actually wrong, configurable severity threshold
- 📱 **Action buttons on your phone** – Telegram bot with Apply / Snooze / Ignore, no SSH needed
- 🖥️ **Web dashboard** – glanceable view at any time, login once with a token
- 🔧 **REST API + OpenAPI docs** – integrate with anything (mobile apps, dashboards, scripts)
- ⏰ **systemd-native** – installs as a timer, runs every 4 hours by default
- 🔁 **Pairs with `unattended-upgrades`** – fully automated patching: detect (watchlog) + install (apt)
- 💓 **Heartbeat** – optional public `/status.json` so external monitors know watchlog itself is alive
- 📋 **Audit trail** – every run archived as JSON in `/var/log/watchlog/`
- 🧩 **Pluggable** – one file per check, one file per reporter; easy to add your own

## Quick start

```bash
# 1. Install (latest from main)
pip install git+https://github.com/Belikebee1/watchlog.git

# 2. Configure
sudo mkdir -p /etc/watchlog
sudo curl -o /etc/watchlog/config.yaml \
  https://raw.githubusercontent.com/Belikebee1/watchlog/main/config.example.yaml
sudo $EDITOR /etc/watchlog/config.yaml

# 3. Run once to verify
sudo watchlog run

# 4. Enable systemd timer (every 4 hours by default)
sudo watchlog install
systemctl list-timers watchlog

# 5. Pair with unattended-upgrades for auto-patching (recommended)
echo 'APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";' | sudo tee /etc/apt/apt.conf.d/20auto-upgrades

sudo sed -i 's|//Unattended-Upgrade::Mail "";|Unattended-Upgrade::Mail "you@example.com";|' \
    /etc/apt/apt.conf.d/50unattended-upgrades

systemctl list-timers apt-daily-upgrade watchlog
```

## How it works in practice

watchlog only **detects** and **notifies**. To actually **apply** security patches automatically, pair it with `unattended-upgrades` (Ubuntu's built-in tool, often disabled by default). Together they give you end-to-end automated security with no SSH session needed.

### Typical security update – start to finish

```
🔘  14:00 UTC  Ubuntu releases security update
                  └─ package appears in -security suite
                  └─ Hetzner / your mirror syncs within ~30 min
       │
🔘  16:00 UTC  watchlog runs (every 4 hours)
                  └─ detects via `apt list --upgradable`
                  └─ escalates to CRITICAL severity
                  └─ 📧 email: "1 security update available"
                  └─ 📋 /status.json heartbeat updated
       │
🔘  06:00 UTC next day  unattended-upgrades runs (daily)
                  └─ installs only -security packages
                  └─ reboots if kernel update (default 03:30, won't reboot if users logged in)
                  └─ 📧 email: "Successfully installed: php8.3-fpm"
       │
🔘  08:00 UTC  watchlog runs again
                  └─ confirms security update is gone
                  └─ severity drops back to OK
```

**Total time-to-patch: ~16 hours** from Ubuntu release to fully patched, fully automatic.

### Two cooperating timers

| Timer | Schedule | Role | Outputs |
|---|---|---|---|
| **`watchlog.timer`** | every 4 hours (00, 04, 08, 12, 16, 20 UTC) | Detects + notifies | email when WARN/CRITICAL · `/status.json` · `/var/log/watchlog/*.json` |
| **`apt-daily-upgrade.timer`** | daily ~06:00 UTC | Installs security updates | email on change · auto-reboot if kernel update · `/var/log/unattended-upgrades/` |

## Checks

| Name | What it checks | Default severity |
|---|---|---|
| `apt_updates` | upgradable packages, with security flag escalation | CRITICAL on security |
| `ssl_certs` | Let's Encrypt cert expiry | WARN <30d, CRITICAL <7d |
| `disk_space` | filesystem usage per mount | WARN >80%, CRITICAL >90% |
| `memory` | free RAM (`MemAvailable`) | WARN <500MB |
| `services` | configured services must be `active` | CRITICAL if down |
| `docker_images` | local digest vs registry `:latest` | INFO if outdated |
| `ip_blacklist` | Spamhaus, Barracuda, SpamCop, SORBS | CRITICAL if listed |
| `dns_records` | SPF/DKIM/DMARC/MX/A presence regression | CRITICAL if missing |
| `ssh_brute` | failed SSH logins in last 24h | WARN >threshold |
| `fail2ban_stats` | jail count, currently banned, required jails active | CRITICAL if service down · WARN on missing jails |
| `open_ports` | new listening ports vs baseline (intrusion signal) | WARN if new ports detected |
| `file_integrity` | AIDE filesystem checksums vs baseline | CRITICAL on changed/removed file |

## Reporters

| Name | Channel | Use case |
|---|---|---|
| `stdout` | terminal (rich/colored) | manual runs, CI |
| `email` | SMTP | scheduled runs |
| `telegram` | Telegram bot | interactive notifications with action buttons (Apply / Snooze / Ignore) |
| `json` | JSON file (per-day archive in `/var/log/watchlog/`) | audit / machine consumption |
| `status_file` | small JSON heartbeat | dead-man's-switch – serve as public URL, monitor externally |

### Heartbeat / dead-man's-switch

The `status_file` reporter writes a small `status.json` after every run. Mount that file under a public URL (e.g. via Nginx) and any external monitor can poll it to confirm watchlog itself is still firing. Schema:

```json
{
  "schema_version": 1,
  "ran_at": "2026-05-02T07:46:44+00:00",
  "host": "myserver",
  "watchlog_version": "0.1.0",
  "worst_severity": "WARN",
  "checks_total": 9,
  "counts": {"OK": 7, "INFO": 1, "WARN": 1, "CRITICAL": 0},
  "actionable": [{"check": "...", "severity": "...", "title": "..."}]
}
```

If `ran_at` becomes stale (older than your timer interval + grace), the timer has stopped firing – investigate immediately.

## Configuration

See [`config.example.yaml`](config.example.yaml) for the full reference.

```yaml
notifications:
  email:
    enabled: true
    to: you@example.com
    smtp_host: 127.0.0.1
    only_when: warn  # ok / info / warn / critical

  status_file:
    enabled: true
    path: /var/www/html/watchlog/status.json  # serve at https://your-domain/status.json

checks:
  apt_updates:
    enabled: true
    security_severity: critical
  ssl_certs:
    enabled: true
    paths: [/etc/letsencrypt/live]
    warn_days: 30
    critical_days: 7
```

## Architecture

```
watchlog/
├── src/watchlog/
│   ├── core/          # config, severity, runner, check base
│   ├── checks/        # one file = one check (apt_updates, ssl_certs, ...)
│   ├── reporters/     # output channels (email, status_file, ...)
│   └── cli.py         # CLI entry point (run, list-checks, install)
└── ops/systemd/       # systemd unit + timer templates
```

## Telegram bot (v0.2)

watchlog can push alerts to a Telegram chat with **inline action buttons**. Click a button on your phone, the bot runs the action on the server, and replies with the result. No webhook, no public HTTPS endpoint – uses long-polling.

### Setup (5 minutes)

```bash
# Walks you through BotFather + @userinfobot to get token & chat_id
sudo watchlog telegram setup

# Edit /etc/watchlog/config.yaml – set notifications.telegram.enabled: true
#   and paste the bot_token and chat_id from setup wizard

# Install + start bot daemon (always-on, listens for button clicks)
sudo watchlog telegram install-service
sudo systemctl start watchlog-bot
journalctl -u watchlog-bot -f       # tail logs
```

### What the buttons do

| Button | Action |
|---|---|
| ✅ **Apply security updates** | Runs `unattended-upgrade -v` and posts the output |
| 🔄 **Run watchlog now** | Triggers a fresh `watchlog run` and posts the result |
| ⏰ **Snooze `<check>` 4h** | Silences alerts for that one check for 4 hours |
| 🚫 **Ignore `<check>`** | Silences until manually un-ignored via `/clearignores` |

### Bot commands (text messages)

| Command | What it does |
|---|---|
| `/help` or `/start` | Show command list |
| `/status` | List currently snoozed/ignored checks |
| `/runnow` | Run watchlog and post the report |
| `/clearignores` | Un-ignore all checks |

The daemon only accepts callbacks from the configured `chat_id` – any other chat is silently rejected and logged.

## REST API + Web dashboard (v0.3)

watchlog ships with an optional FastAPI daemon that exposes the same data the Telegram bot uses, plus a self-hosted web dashboard. Useful when you want a glanceable view of multiple checks at once, or when you want to integrate watchlog with other tooling (mobile apps, monitoring dashboards, scripts).

### Setup

```bash
# Install with API extras
pip install 'git+https://github.com/Belikebee1/watchlog.git#egg=watchlog[api]'

# Generate token (writes to /etc/watchlog/config.yaml under api.token)
sudo watchlog api setup

# Install + start daemon (binds to 127.0.0.1:8765 by default)
sudo watchlog api install-service
sudo systemctl start watchlog-api

# Verify
curl https://api.your-domain/api/v1/health
```

Put nginx in front with TLS, e.g. `api.watchlog.pl`. The daemon binds to `127.0.0.1` so it's never reachable directly from the internet.

### Endpoints (all require `Authorization: Bearer <token>` except `/api/v1/health`)

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/` | Dashboard SPA |
| `GET` | `/api/v1/health` | Liveness check (public) |
| `GET` | `/api/v1/status` | Latest heartbeat with `age_seconds` |
| `GET` | `/api/v1/reports` | List of archived run dates |
| `GET` | `/api/v1/reports/{date}` | Runs for a specific day |
| `POST` | `/api/v1/runs` | Trigger fresh `watchlog run` |
| `GET` | `/api/v1/state` | Current snoozes + ignores |
| `POST` | `/api/v1/state/snooze` | `{check, hours}` |
| `POST` | `/api/v1/state/ignore` | `{check}` |
| `DELETE` | `/api/v1/state/snooze/{check}` | Un-snooze |
| `DELETE` | `/api/v1/state/ignore/{check}` | Un-ignore |
| `POST` | `/api/v1/actions/apply-security` | Run `unattended-upgrade -v` |

Full OpenAPI/Swagger UI at `/docs`.

### Dashboard

Vanilla HTML/JS, no framework. Login screen accepts the token, stores it in `localStorage`, and shows:

- Severity banner (color-coded by worst severity)
- Action buttons: Apply security · Run watchlog now · Clear snoozes
- Per-check list with inline Snooze 4h / Ignore / Clear buttons
- Output drawer for command results (apt, watchlog run output)
- Auto-refresh every 60s

## Roadmap

- ✅ **v0.1** – 9 checks, stdout/email/JSON/status_file reporters, systemd installer
- ✅ **v0.2** – Telegram bot reporter with interactive buttons (Apply / Snooze / Ignore)
- ✅ **v0.3** – REST API + web dashboard with Bearer auth, action endpoints
- ✅ **v0.4** – fail2ban stats, open-ports baseline diff, file integrity (AIDE)
- 📱 **v0.5** – Native mobile app (iOS/Android with FCM push) – uses v0.3 API as backend

## License

MIT – see [LICENSE](LICENSE).
