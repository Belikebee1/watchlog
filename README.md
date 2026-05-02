# watchlog

Server health and security monitor for Linux servers. Single-file Python tool that runs daily checks (apt updates, SSL certs, services, disk, mail blacklists, etc.) and sends notifications via email or Telegram.

Built for self-hosted setups where you want to know **what needs attention without logging in to check**.

## Features

- 🔒 **Security-focused** — APT security updates flagged as critical, IP blacklist monitoring, SSH brute-force detection
- 🔌 **Pluggable** — checks and reporters are independent modules, easy to add new ones
- 📧 **Multi-channel notifications** — email (SMTP), Telegram bot (with action buttons), stdout, JSON
- ⏰ **systemd-native** — installs as systemd timer for daily runs
- 🚦 **Severity levels** — only notifies when `WARN` or `CRITICAL` (no spam in quiet times)
- 📋 **Audit trail** — every run logged to `/var/log/watchlog/`

## Quick start

```bash
# Install (latest from main)
pip install git+https://github.com/Belikebee1/watchlog.git

# Or for development
git clone https://github.com/Belikebee1/watchlog.git
cd watchlog
pip install -e ".[dev]"

# Configure
sudo mkdir -p /etc/watchlog
sudo cp config.example.yaml /etc/watchlog/config.yaml
sudo $EDITOR /etc/watchlog/config.yaml

# Run once (manual)
sudo watchlog run

# Install as systemd timer (daily 08:00)
sudo watchlog install

# Check timer status
systemctl list-timers watchlog
```

## Checks

| Name | What it checks | Default severity |
|---|---|---|
| `apt_updates` | apt list of upgradable packages | INFO |
| `apt_security` | apt security updates available | CRITICAL |
| `ssl_certs` | Let's Encrypt cert expiry | WARN <30d, CRITICAL <7d |
| `disk_space` | filesystem usage | WARN >80%, CRITICAL >90% |
| `memory` | free RAM | WARN <500MB |
| `services` | configured services must be `active` | CRITICAL if not |
| `docker_images` | digest vs `:latest` for configured images | INFO if newer available |
| `ip_blacklist` | Spamhaus, Barracuda, SpamCop, SORBS | CRITICAL if listed |
| `dns_records` | SPF/DKIM/DMARC/A/MX presence | CRITICAL if missing |
| `ssh_brute` | failed SSH logins in last 24h | WARN >threshold |

## Reporters

| Name | Channel | Use case |
|---|---|---|
| `stdout` | terminal (rich/colored) | manual runs, CI |
| `email` | SMTP | scheduled runs |
| `telegram` | Telegram bot | interactive notifications with buttons (in v0.2) |
| `json` | JSON file | machine consumption |

## Configuration

See [config.example.yaml](config.example.yaml) for a full example.

```yaml
notifications:
  email:
    to: you@example.com
    smtp_host: 127.0.0.1
    only_when: warn  # ok / info / warn / critical

checks:
  apt_security:
    enabled: true
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
│   ├── core/          # config, severity, runner
│   ├── checks/        # one file = one check
│   ├── reporters/     # output channels
│   └── cli.py         # CLI entry point
└── ops/systemd/       # unit + timer files
```

## License

MIT — see [LICENSE](LICENSE).
