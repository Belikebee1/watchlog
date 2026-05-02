# watchlog

Server health and security monitor for Linux servers. Python tool that runs scheduled checks (apt updates, SSL certs, services, disk, mail blacklists, SSH brute-force, etc.) and sends notifications via email — or, paired with `unattended-upgrades`, gives you fully-automated security patching with no SSH session needed.

Built for self-hosted setups where you want to know **what needs attention without logging in to check**.

🌐 **Landing page:** [watchlog.pl](https://watchlog.pl) (also in Polish at [watchlog.pl/pl/](https://watchlog.pl/pl/))

## Features

- 🔒 **Security-focused** — APT security updates flagged as critical, IP blacklist monitoring, SSH brute-force detection
- 🤫 **No spam** — email only when something is actually wrong, configurable severity threshold
- 🔌 **Pluggable** — checks and reporters are independent modules, easy to add new ones
- 📧 **Multi-channel notifications** — email (SMTP), Telegram bot (with action buttons, v0.2), stdout, JSON
- ⏰ **systemd-native** — installs as systemd timer (default: every 4 hours)
- 📋 **Audit trail** — every run archived as JSON in `/var/log/watchlog/`
- 💓 **Heartbeat** — optional public `/status.json` for external dead-man's-switch monitoring

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

### Typical security update — start to finish

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

## Reporters

| Name | Channel | Use case |
|---|---|---|
| `stdout` | terminal (rich/colored) | manual runs, CI |
| `email` | SMTP | scheduled runs |
| `telegram` | Telegram bot | interactive notifications with buttons (v0.2) |
| `json` | JSON file (per-day archive in `/var/log/watchlog/`) | audit / machine consumption |
| `status_file` | small JSON heartbeat | dead-man's-switch — serve as public URL, monitor externally |

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

If `ran_at` becomes stale (older than your timer interval + grace), the timer has stopped firing — investigate immediately.

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

## Roadmap

- ✅ **v0.1** — 9 checks, stdout/email/JSON/status_file reporters, systemd installer
- 🤖 **v0.2** — Telegram bot reporter with interactive buttons (Apply / Postpone / Ignore)
- 📱 **v0.3** — REST API daemon, web dashboard, action endpoints for mobile clients
- 🛡️ **v0.4** — fail2ban stats, open-ports baseline diff, file integrity (AIDE), CVE matching

## License

MIT — see [LICENSE](LICENSE).
