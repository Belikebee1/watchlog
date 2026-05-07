"""Human-readable explanations for every check, served to mobile clients.

Each entry has four bilingual fields (EN + PL):

  title         — short heading shown in the explainer sheet
  what          — what this check actually does in plain language
  why           — why a sysadmin should care if this fires
  remediation   — concrete next steps when the check is non-OK

Mobile picks the language based on device locale (any locale starting with
"pl" → Polish; everything else falls back to English). New languages can be
added without touching the API contract — just add a key like "de" alongside
the existing ones.

This is *static* metadata — generic to any watchlog deployment. It does not
contain server-specific data, secrets, or anything sensitive. We still gate
the endpoint behind `read` scope to avoid an open documentation API on a
host that may be otherwise locked down.

Adding a new check? Add an entry here too. The API endpoint enumerates this
dict, so missing entries silently disappear from the mobile explainer.
"""

from __future__ import annotations

from typing import Any

# Severity legend — universal, hardcoded on mobile too as a fallback so
# the legend works offline. Exposed via the API for completeness.
SEVERITY_LEGEND: dict[str, dict[str, dict[str, str]]] = {
    "OK": {
        "label": {"en": "OK", "pl": "OK"},
        "description": {
            "en": "Everything is normal. No action needed.",
            "pl": "Wszystko w porządku. Nic nie trzeba robić.",
        },
    },
    "INFO": {
        "label": {"en": "Info", "pl": "Info"},
        "description": {
            "en": "Something noteworthy, but not urgent. Read when you have time.",
            "pl": "Coś zauważalnego, ale nie pilnego. Przeczytaj gdy będziesz miał chwilę.",
        },
    },
    "WARN": {
        "label": {"en": "Warning", "pl": "Ostrzeżenie"},
        "description": {
            "en": "A condition that should be looked at soon — within hours, not weeks. "
                  "Won't break the server immediately, but ignored long enough it might.",
            "pl": "Coś co warto sprawdzić w ciągu godzin, nie tygodni. Nie ubije serwera "
                  "natychmiast, ale ignorowane zbyt długo może.",
        },
    },
    "CRITICAL": {
        "label": {"en": "Critical", "pl": "Krytyczne"},
        "description": {
            "en": "Something is broken, exposed, or about to expire. Act now.",
            "pl": "Coś jest popsute, narażone albo lada chwila wygaśnie. Działaj teraz.",
        },
    },
}


CHECK_INFO: dict[str, dict[str, Any]] = {
    "apt_updates": {
        "title": {"en": "APT updates", "pl": "Aktualizacje APT"},
        "what": {
            "en": "Counts how many Debian/Ubuntu packages are upgradable — and how many of those are flagged as security updates.",
            "pl": "Liczy ile paczek Debian/Ubuntu można zaktualizować — i ile z nich to aktualizacje bezpieczeństwa.",
        },
        "why": {
            "en": "Unpatched security holes are how most servers get owned. The faster you patch, the smaller your window of exposure.",
            "pl": "Niezałatane dziury bezpieczeństwa to najczęstszy sposób na przejęcie serwera. Im szybciej łatasz, tym krócej jesteś narażony.",
        },
        "remediation": {
            "en": "Run `apt upgrade` for everything, or `unattended-upgrade -v` to apply only security updates. The mobile app's \"Apply security\" button does the latter.",
            "pl": "`apt upgrade` zaktualizuje wszystko, `unattended-upgrade -v` tylko bezpieczeństwo. Przycisk \"Apply security\" w aplikacji robi to drugie.",
        },
    },
    "ssl_certs": {
        "title": {"en": "TLS certificates", "pl": "Certyfikaty TLS"},
        "what": {
            "en": "Checks every Let's Encrypt certificate under /etc/letsencrypt/live and reports the soonest expiry date.",
            "pl": "Sprawdza każdy certyfikat Let's Encrypt w /etc/letsencrypt/live i zgłasza najwcześniejszą datę wygaśnięcia.",
        },
        "why": {
            "en": "An expired certificate makes your sites unreachable for any modern browser. Auto-renewal usually works, but when it silently fails, this check is your safety net.",
            "pl": "Wygasły certyfikat sprawia że strona przestaje działać w jakiejkolwiek nowoczesnej przeglądarce. Auto-odnawianie zwykle działa, ale gdy po cichu się wysypie, ten check to ostatnia linia obrony.",
        },
        "remediation": {
            "en": "Run `certbot renew --dry-run` to see what's failing. If a hook is broken, fix it. If renewal works, just wait — it usually runs daily via systemd timer.",
            "pl": "`certbot renew --dry-run` pokaże co się sypie. Jeśli hook jest popsuty, napraw go. Jeśli renewal działa, czekaj — zwykle uruchamia się codziennie przez systemd timer.",
        },
    },
    "disk_space": {
        "title": {"en": "Disk space", "pl": "Miejsce na dysku"},
        "what": {
            "en": "Reports usage on every mounted filesystem (excluding tmpfs and snap mounts) against configurable warn/critical thresholds.",
            "pl": "Raportuje zajętość każdego zamontowanego systemu plików (poza tmpfs i snap) względem konfigurowalnych progów warn/critical.",
        },
        "why": {
            "en": "A full disk freezes services in subtle ways: Postgres can't write WAL, mail queues stop, logs disappear. Catching it at 80% gives you time; at 100% you're firefighting.",
            "pl": "Pełny dysk zamraża usługi po cichu: Postgres nie zapisze WAL, kolejka maili stanie, logi przestaną się pisać. Wyłapanie przy 80% daje czas; przy 100% już gasisz pożar.",
        },
        "remediation": {
            "en": "Find the heavy directories with `sudo du -h --max-depth=1 / | sort -rh | head`. Common offenders: Docker volumes, journald, old logs, /tmp.",
            "pl": "Najgrubszych katalogów szukaj przez `sudo du -h --max-depth=1 / | sort -rh | head`. Częste winowajcy: Docker volumes, journald, stare logi, /tmp.",
        },
    },
    "memory": {
        "title": {"en": "Memory", "pl": "Pamięć"},
        "what": {
            "en": "Reads /proc/meminfo and reports MemAvailable (the kernel's estimate of usable RAM, accounting for caches and reclaimable slabs).",
            "pl": "Odczytuje /proc/meminfo i raportuje MemAvailable (jądro szacuje ile RAM można jeszcze użyć, uwzględniając cache i odzyskiwalne sloty).",
        },
        "why": {
            "en": "When MemAvailable drops below a few hundred MB the kernel will start swapping aggressively, OOM-killing processes, or both. Either way services flap.",
            "pl": "Gdy MemAvailable spada do kilkuset MB jądro zaczyna agresywnie używać swap, ubijać procesy OOM, albo i jedno i drugie. Tak czy inaczej, usługi padają.",
        },
        "remediation": {
            "en": "Find the hog with `ps aux --sort=-rss | head`. Common causes: a leaking app, n8n with too many workers, Postgres shared_buffers misconfigured.",
            "pl": "Najobżarniejszy proces wyłapie `ps aux --sort=-rss | head`. Częste przyczyny: app z wyciekiem pamięci, za dużo workerów n8n, źle skonfigurowane shared_buffers Postgresa.",
        },
    },
    "services": {
        "title": {"en": "Services", "pl": "Usługi"},
        "what": {
            "en": "Verifies that every systemd unit listed in `services.must_be_active` is in the `active` state.",
            "pl": "Sprawdza czy każda usługa systemd z `services.must_be_active` jest w stanie `active`.",
        },
        "why": {
            "en": "If postfix is down, no mail; if nginx is down, no website. Sometimes a unit dies and systemd can't restart it (failed restart limit). Catching that quickly is the whole point.",
            "pl": "Postfix padł = nie ma maila; nginx padł = nie ma strony. Czasem usługa umiera i systemd nie potrafi jej zrestartować (limit prób). Sens tego checka to wyłapanie tego szybko.",
        },
        "remediation": {
            "en": "Inspect with `systemctl status <name>` and `journalctl -u <name> -n 100`. Restart with `systemctl restart <name>`. If it keeps failing, fix the underlying error rather than restart-looping.",
            "pl": "Sprawdź `systemctl status <nazwa>` i `journalctl -u <nazwa> -n 100`. Restart przez `systemctl restart <nazwa>`. Jeśli ciągle się sypie, napraw przyczynę, nie loop'uj restartami.",
        },
    },
    "docker_images": {
        "title": {"en": "Docker images", "pl": "Obrazy Dockera"},
        "what": {
            "en": "For each image in your config, compares the local digest with the registry's `latest` tag.",
            "pl": "Dla każdego obrazu z configu porównuje lokalny digest z registry tag'iem `latest`.",
        },
        "why": {
            "en": "Pinned images (e.g. postgres:16-alpine) get security patches via new digests under the same tag. Without pulling them, you're stuck on old code.",
            "pl": "Przypięte obrazy (np. postgres:16-alpine) dostają poprawki bezpieczeństwa przez nowe digesty pod tym samym tagiem. Bez ściągania ich tkwisz na starym kodzie.",
        },
        "remediation": {
            "en": "Update with `docker compose pull && docker compose up -d`. Always read changelogs before pulling Postgres or other stateful databases.",
            "pl": "Aktualizacja: `docker compose pull && docker compose up -d`. Zawsze czytaj changelog przed pull'em Postgresa albo innych baz danych ze stanem.",
        },
    },
    "ip_blacklist": {
        "title": {"en": "IP blacklist", "pl": "Czarne listy IP"},
        "what": {
            "en": "Queries DNSBLs (Spamhaus, SpamCop, Barracuda, SORBS) for the server's outbound IP.",
            "pl": "Pyta DNSBL (Spamhaus, SpamCop, Barracuda, SORBS) o IP wychodzący serwera.",
        },
        "why": {
            "en": "If you run mail, being on a blacklist means Gmail/Outlook silently drop your messages. The faster you find out, the faster you can request delisting.",
            "pl": "Jeśli wysyłasz pocztę, bycie na blackliście znaczy że Gmail/Outlook po cichu wyrzucają Twoje wiadomości. Im szybciej się dowiesz, tym szybciej zgłosisz delisting.",
        },
        "remediation": {
            "en": "Find which list flagged you, follow that list's removal procedure (usually a web form). Spamhaus is most strict and most widely-respected.",
            "pl": "Sprawdź która lista Cię oflagowała, idź zgodnie z jej procedurą zdjęcia z listy (zwykle formularz na stronie). Spamhaus jest najsurowszy i najszerzej szanowany.",
        },
    },
    "dns_records": {
        "title": {"en": "DNS records", "pl": "Rekordy DNS"},
        "what": {
            "en": "For every domain you manage, verifies the required records exist (typically MX, SPF, DMARC).",
            "pl": "Dla każdej domeny którą obsługujesz sprawdza czy istnieją wymagane rekordy (typowo MX, SPF, DMARC).",
        },
        "why": {
            "en": "Missing SPF or DMARC = your mail flagged as spam. Missing MX = no mail delivery at all. DNS providers occasionally drop records during edits — this catches the regression.",
            "pl": "Brak SPF/DMARC = poczta ląduje jako spam. Brak MX = poczta w ogóle nie dociera. Provider DNS czasem zgubi rekord przy edycji — ten check wyłapie regres.",
        },
        "remediation": {
            "en": "Log in to your DNS provider, re-add the missing record. Verify with `dig <domain> TXT +short`.",
            "pl": "Zaloguj się do DNS providera, dodaj brakujący rekord. Sprawdź przez `dig <domena> TXT +short`.",
        },
    },
    "ssh_brute": {
        "title": {"en": "SSH brute force", "pl": "Brute-force SSH"},
        "what": {
            "en": "Counts failed SSH login attempts in the last 24 hours from /var/log/auth.log.",
            "pl": "Liczy nieudane próby logowania SSH z ostatnich 24h z /var/log/auth.log.",
        },
        "why": {
            "en": "Background noise on a public IP is normal (a few hundred to a few thousand attempts/day). A sudden spike — or a single IP punching above the rest — is worth investigating.",
            "pl": "Hałas na publicznym IP to norma (kilkaset do kilku tysięcy prób dziennie). Nagły skok — albo pojedynczy IP wybijający się ponad resztę — warto sprawdzić.",
        },
        "remediation": {
            "en": "fail2ban should already be banning the worst offenders. If you want extra safety: disable password auth, allow only key-based; rate-limit with iptables; move SSH to a non-standard port.",
            "pl": "fail2ban powinien już banować najgorszych. Dla większego bezpieczeństwa: wyłącz auth hasłem, zostaw tylko klucze; rate-limit przez iptables; przenieś SSH na niestandardowy port.",
        },
    },
    "fail2ban_stats": {
        "title": {"en": "fail2ban stats", "pl": "Statystyki fail2ban"},
        "what": {
            "en": "Reads `fail2ban-client status` to verify required jails are running and reports current/total ban counts.",
            "pl": "Sprawdza `fail2ban-client status` żeby zweryfikować że wymagane jaile są uruchomione, raportuje aktualną/całkowitą liczbę banów.",
        },
        "why": {
            "en": "If the sshd jail dies (config error after edit, fail2ban restart hung), brute-force protection is gone. You'd never notice until you check this.",
            "pl": "Jeśli sshd jail padnie (błąd configu po edycji, fail2ban zawiesił się przy restarcie), brak ochrony przed brute-force. Nie zauważysz tego dopóki tego nie sprawdzisz.",
        },
        "remediation": {
            "en": "Restart with `systemctl restart fail2ban`. If a specific jail is missing, look in /etc/fail2ban/jail.d/ for the relevant config.",
            "pl": "Restart przez `systemctl restart fail2ban`. Jeśli brakuje konkretnego jail'a, zajrzyj do /etc/fail2ban/jail.d/ po konfigurację.",
        },
    },
    "open_ports": {
        "title": {"en": "Open ports", "pl": "Otwarte porty"},
        "what": {
            "en": "Captures the set of currently listening TCP/UDP ports and compares it to a saved baseline.",
            "pl": "Zapisuje zestaw aktualnie nasłuchujących portów TCP/UDP i porównuje z zapisanym wzorcem (baseline).",
        },
        "why": {
            "en": "A new listening port is one of the strongest signals that something changed: a new service, a forgotten dev server, or — rarely — a backdoor.",
            "pl": "Nowy nasłuchujący port to jeden z najsilniejszych sygnałów że coś się zmieniło: nowa usługa, zapomniany dev server, albo — rzadko — backdoor.",
        },
        "remediation": {
            "en": "List who's listening with `ss -tlnp`. If the change is intentional, accept the new state: `sudo rm /var/lib/watchlog/ports-baseline.txt && sudo watchlog run --check open_ports`.",
            "pl": "Listę listenerów daje `ss -tlnp`. Jeśli zmiana jest celowa, zaakceptuj nowy stan: `sudo rm /var/lib/watchlog/ports-baseline.txt && sudo watchlog run --check open_ports`.",
        },
    },
    "file_integrity": {
        "title": {"en": "File integrity (AIDE)", "pl": "Integralność plików (AIDE)"},
        "what": {
            "en": "Runs an AIDE check that hashes critical system files and compares them to a known-good database.",
            "pl": "Uruchamia AIDE który hashuje krytyczne pliki systemowe i porównuje z wzorcową bazą.",
        },
        "why": {
            "en": "If a file in /etc, /usr/bin, or /lib changes outside of `apt`, that's suspicious. AIDE catches what nothing else does — including rootkits that hide from `ps`.",
            "pl": "Jeśli plik w /etc, /usr/bin albo /lib zmieni się poza `apt`, to podejrzane. AIDE łapie to czego nie złapie nic innego — w tym rootkity ukrywające się przed `ps`.",
        },
        "remediation": {
            "en": "Investigate every reported change. Legitimate ones (e.g. a manual edit you forgot) get accepted with `aide --update`. Unexpected changes warrant a deeper audit.",
            "pl": "Każdą zgłoszoną zmianę zbadaj. Legalne (np. ręczna edycja o której zapomniałeś) akceptuj przez `aide --update`. Nieoczekiwane zasługują na głębszy audyt.",
        },
    },
}
