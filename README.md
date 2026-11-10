
```
     __    __    __
  __/  \__/  \__/  \__    _   _  ___  _   _ _______   ______ ___  __  __ ____
 /  \__/  \__/  \__/  \  | | | |/ _ \| \ | | ____\ \ / / ___/ _ \|  \/  | __ )
 \__/  \__/  \__/  \__/  | |_| | | | |  \| |  _|  \ V / |  | | | | |\/| |  _ \
 /  \__/  \__/  \__/  \  |  _  | |_| | |\  | |___  | || |__| |_| | |  | | |_) |
 \__/  \__/  \__/  \__/  |_| |_|\___/|_| \_|_____| |_| \____\___/|_|  |_|____/
    \__/  \__/  \__/
```

**Combs through your honeypot logs.**

Offline, multi-sensor analyzer for **Cowrie** and **Conpot**. It builds a self-contained dashboard and
shareable IOC feeds (CSV, JSON, plain blocklists and **STIX 2.1** for TAXII).

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
![Offline](https://img.shields.io/badge/runs-fully%20offline-orange)


---

## Why HONEYCOMB?

Running more than one honeypot quickly turns into a pile of `cowrie.json.2026-11-07.gz` files spread
across machines. HONEYCOMB takes one folder per sensor and gives you:

- **One dashboard for the whole fleet.** It has an overview, a tab per sensor and an IOC browser, all in
  a single HTML file with no CDN or internet connection needed.
- **Cross-sensor correlation.** It shows which attackers hit more than one of your sensors, which are
  usually the IOCs most worth sharing.
- **A feed you can publish safely.** Your sensors' own IPs, private addresses and benign services
  are kept out of the exports automatically.
- **STIX 2.1 that behaves properly in TAXII.** Indicator IDs stay the same between runs, `created`
  never changes, `modified` only moves when the indicator actually changes, and every indicator gets
  a `valid_until`.
- **No dependencies.** Python 3.8+ standard library only. Copy the script and run it.

## Screenshots

| Overview | IOC browser |
|---|---|
| ![Overview](docs/overview.png) | ![IOC browser](docs/iocs.png) |

## Quick start

```bash
git clone https://github.com/really-gabagool/honeycomb.git
cd honeycomb
python honeycomb.py /path/to/honeypot-logs
```

Then open `honeycomb-report/dashboard.html` in any browser.

## Log folder layout

Point HONEYCOMB at a folder with **one child folder per sensor**. Files are found recursively, `.gz`
is fine, and each file's log type is detected by name and then by content.

```
honeypot-logs/
├── sensors.json               (optional, see below)
├── cowrie-nyc1/
│   ├── cowrie.json
│   ├── cowrie.json.2026-11-07
│   └── cowrie.json.2026-11-06.gz
├── cowrie-blr1/
│   └── cowrie.json*
└── conpot-ics1/
    └── conpot.json*  and/or  conpot.log*
```

| Source | What is read |
|---|---|
| Cowrie | the JSON log (`cowrie.json*`). `cowrie.log` is skipped because it duplicates the JSON log. |
| Conpot | the JSON logger (`conpot.json*`), with best-effort parsing of the text log (`conpot.log*`) |

Cowrie's `downloads/` and `tty/` folders are always skipped, so captured malware samples are never
opened as logs. Overlapping copies of the same log, such as a file and its `.gz`, are de-duplicated.

## Usage

```bash
# everything, default output folder
python honeycomb.py C:\honeypot-logs

# a date range into a specific folder
python honeycomb.py C:\honeypot-logs --out C:\reports\today --since 2026-11-01 --until 2026-11-08

# the last 7 days, ignoring your own management IP
python honeycomb.py C:\honeypot-logs --days 7 --exclude 203.0.113.7

# build a public feed + a dashboard that is safe to post
python honeycomb.py C:\honeypot-logs --anonymize-sensors --min-confidence medium --public
```

### Options

| Option | Description |
|---|---|
| `root` | Folder containing one child folder per sensor |
| `--out DIR` | Output folder (default `./honeycomb-report`) |
| `--since YYYY-MM-DD` | Only events on/after this date (00:00 UTC) |
| `--until YYYY-MM-DD` | Only events **before** this date (exclusive) |
| `--days N` | Only the last N days (overrides `--since`) |
| `--exclude IP/CIDR` | Ignore these sources (your own IPs). Repeatable or comma-separated |
| `--include-private` | Keep RFC1918 / loopback / reserved source IPs (dropped by default) |
| `--allowlist FILE` | Extra benign domains, one per line (subdomains match), never exported |
| `--bruteforce-threshold N` | Failed logins from one IP before tagging `bruteforce` (default 5) |
| `--min-confidence low\|medium\|high` | Lowest confidence written to the shareable exports |
| `--anonymize-sensors` | Use stable, non-reversible names like `sensor-3fa9c1` in exports |
| `--public` | Make `dashboard.html` safe to publish (see [Publishing](#publishing-a-feed)) |
| `--tlp clear\|green\|amber\|red` | TLP marking on STIX objects (default `clear`) |
| `--org NAME` | Producer name on the STIX identity (default `HONEYCOMB`) |
| `--valid-days N` | STIX `valid_until` = last seen + N days (default 30, `0` = no expiry) |
| `--state FILE` / `--no-state` | Where to keep state between runs (see [State file](#state-file)) |
| `--dedupe line\|file\|off` | `line` (default) drops repeated lines across overlapping copies. `file` only skips identical files and uses much less memory on large log sets |
| `--conpot-text-too` | Also parse `conpot.log` when `conpot.json` exists (may double count) |
| `--no-banner`, `--no-color` | Quiet the banner / colours (`NO_COLOR` is honoured too) |
| `--version` | Print the version |

### `sensors.json` (optional)

Put this in the log root to give sensors friendly labels and public names, force a log type, skip a
folder, or add excludes and allowlist entries:

```json
{
  "sensors": {
    "cowrie-nyc1": {"label": "Cowrie NYC", "public_name": "sensor-us", "location": "New York"},
    "cowrie-blr1": {"label": "Cowrie Bangalore", "public_name": "sensor-in"},
    "conpot-ics1": {"label": "Conpot ICS", "type": "conpot"},
    "old-box":     {"skip": true}
  },
  "exclude": ["198.51.100.10", "192.0.2.0/24"],
  "allowlist": ["my-uptime-monitor.example"]
}
```

Sensors are shown in the order they are listed here.

## Output

```
honeycomb-report/
├── dashboard.html          overview + one tab per sensor + IOC browser (offline)
├── credentials.csv         attempted username/password pairs (research data, not IOCs)
└── iocs/
    ├── master_iocs.csv     every shareable IOC: type, value, confidence, first/last seen,
    ├── master_iocs.json      sensors, count, tags, context
    ├── stix2_bundle.json   STIX 2.1 indicators, ready for a TAXII server
    ├── ipv4.txt  ipv6.txt  urls.txt  domains.txt  sha256.txt  hassh.txt   plain blocklists
```

All CSV output is protected against spreadsheet formula injection. Attacker-supplied strings like
`=cmd|...` won't run when you open the file in Excel.

## How IOCs are scored

Each IOC gets tags based on what was observed, and its confidence comes from the strongest tag.

| Confidence | STIX score | Triggered by tags such as |
|---|---|---|
| **high** | 85 | `login-success`, `command-exec`, `malware-download`, `download-attempt`, `payload-host`, `downloaded`, `download-failed`, `raw-ip-host`, `persistence`, `privilege-escalation`, `cryptomining`, `tunnel-abuse` |
| **medium** | 60 | `bruteforce`, `multi-sensor`, `ics-scan`, `defense-evasion`, `seen-in-command`, `seen-in-ics-request`, `referenced-host` |
| **low** | 30 | everything else (`scanner`, `login-attempt`, HASSH fingerprints…), plus anything allowlisted |

Commands run in Cowrie are also sorted into behaviour categories (system enum, recon, privilege
escalation, persistence, credential change, download/stage, cryptomining, defense evasion, killing
competitors) for the dashboard.

## What never leaves your machine

Shareable exports are filtered before they're written. These items stay in your local dashboard only:

| Held back | Tag shown in the dashboard |
|---|---|
| Your sensors' own IPs, learned from the logs plus `--exclude`, **including inside URLs** | `own-sensor` |
| Private / reserved addresses and URLs or domains pointing at them | `private-host` |
| Well-known benign services: IP-check sites, package mirrors, big platforms, plus your allowlist | `allowlisted` |
| Domains of shared hosting (GitHub, Pastebin, S3, Discord CDN…). **The full URL is still exported.** | `shared-hosting` |

## Publishing a feed

```bash
python honeycomb.py C:\honeypot-logs --anonymize-sensors --min-confidence medium --public --org "your-handle"
```

- `--anonymize-sensors` replaces sensor names with stable names that can't be reversed.
- `--public` removes local file paths and real sensor names from the dashboard, shows only shareable
  IOCs, and replaces your sensor IPs with `[sensor-ip]` everywhere, including inside captured
  commands and requests.
- Push `iocs/stix2_bundle.json` to your TAXII server. Because the state file tracks object versions,
  re-uploading after every run is safe: unchanged indicators keep the same `modified` timestamp.

## State file

By default HONEYCOMB keeps a small state file at `~/.honeycomb/state-<hash of log root>.json`. It
remembers:

- **first/last seen for every IOC**, so `first_seen` and STIX `valid_from` stay historic even when you
  analyze only `--days 7`
- **STIX object versions**, so `created` never changes and `modified` only changes with the content
- **a random salt** for `--anonymize-sensors`, so names stay stable when you add or remove sensors

> ⚠️ **Don't publish or commit the state file.** The salt is what keeps anonymised sensor names from
> being reversed.

Use `--state FILE` to keep it somewhere specific (always the same file for a given feed), or
`--no-state` to run without one (STIX versioning then becomes approximate). If the file is corrupt,
HONEYCOMB stops instead of quietly starting over, which would give TAXII consumers conflicting
versions of objects they already have.

## Privacy & safety notes

- HONEYCOMB is **read-only** and **offline**. It never contacts the network or the IPs it finds.
- The dashboard only inserts data as plain text and has a strict Content-Security-Policy, so
  attacker-supplied strings in logs can't run as script in your browser.
- `credentials.csv` contains real attacker attempts. Some passwords may be offensive, and some may
  be real leaked credentials, so treat it accordingly.

## Roadmap

- [ ] MedPot (HL7 / FHIR) support
- [ ] SSH public keys as IOCs (`cowrie.client.fingerprint`, `authorized_keys` drops)
- [ ] Decode base64 one-liners and re-scan them for URLs/IPs
- [ ] Known research-scanner list (Shodan, Censys…) with an option to keep them out of feeds
- [ ] MITRE ATT&CK technique IDs on command categories
- [ ] Campaign clustering with STIX relationships between IPs, URLs and hashes
- [ ] Per-session drill-down in the dashboard

## Contributing

Issues and pull requests are welcome, especially sample logs from other Cowrie/Conpot setups
(please sanitise your own IPs first) and parsers for more honeypots.

## License

Released under the MIT License. See [LICENSE](LICENSE).

---

<div align="center">Made by <a href="https://github.com/really-gabagool">@really-gabagool</a> 🐝</div>
