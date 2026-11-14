# Changelog

## 1.3.4 - 2026-11-13

### Changed
- An IP that only scanned stays **low** even when it hit more than one sensor. Mass scanners sweep every address, so "seen on several sensors" says nothing about intent. `multi-sensor` is still tagged and shown on the dashboard, and it still counts for IPs that did something (logged in, brute-forced, probed ICS...). Every medium or high IP in the feed has now done more than connect.

## 1.3.3 - 2026-11-13

### Changed
- **One default state file:** `~/.honeycomb/state.json`, shared by all runs. Before, the state file was named after the log folder, so a new folder per log pull silently started a new feed (new `first_seen`, new STIX `created`). If you used the old default, move your `state-<hash>.json` to `state.json` to keep its history.
- URLs passed to `wget`/`curl`/`tftp`/`ftpget` in a shell command are now tagged `download-url`, rated **high**, with their host a `payload-host`, whether the host is an IP or a domain. Before, only raw-IP hosts were high. URLs that are merely mentioned (`echo http://…`) stay medium.
- `multi-source` counts distinct /24 (IPv6 /48) networks, not IPs.

### Added
- Cowrie `client.fingerprint`: public keys attackers try become `ssh-key` IOCs (`SHA256:` fingerprint), written to `iocs/ssh_keys.txt` and shown on a dashboard card. They're medium only when sources in different networks share a key.
- Cowrie `telnet.exploit_attempt`: the source is tagged `exploit-attempt` plus the CVE (e.g. `cve-2026-24061`), with ATT&CK T1190.

## 1.3.2 - 2026-11-13

### Changed
- URLs inside an exploit request are now treated as payloads. Examples: a Conpot/HTTP request, or a honeypot payload that downloads and runs something (`wget …; sh …`). They're tagged `exploit-payload`, rated **high** and mapped to T1190 + T1105, and their host is a `payload-host`, the same as a Cowrie `wget`. Before, they were medium and their domains `referenced-host`.
- Exploit detection runs on the URL-decoded request, so percent-encoded droppers (`wget%20http%3A%2F%2F…`) are recognised too.

## 1.3.1 - 2026-11-13

### Fixed
- URLs in network traffic (Conpot/HTTP requests, honeypot payloads, Log4Shell callbacks) are URL-decoded before extraction. `wget+http://x/Mozi.m+-O+/tmp/a` now gives `http://x/Mozi.m`, not a URL that never matches anything.

### Changed
- A login with no follow-up activity is **medium**, not high. Cowrie accepts almost any password, so a login alone mostly means a bot tried a common password. Commands, downloads, exploits and tunnelling still make an IP high.
- HASSH fingerprints are always **low**. Previously, a client seen on two sensors was bumped to medium.

### Added
- `scanners.txt`: published research-scanner ranges (Palo Alto Xpanse, Shodan, Shadowserver), loaded automatically and held back from exports. It catches scanners whose network is registered to a cloud or transit provider, which ASN-name matching misses.
- `--scanners FILE` (repeatable), `"scanners"` in sensors.json, and `--no-scanner-list`.

## 1.3.0 - 2026-11-13
First public release.

### Fixed
- Native MedPot logs (`"ip"` key, `2018.09.09 17:20:49` timestamps) are now recognised; before, the whole sensor was skipped.
- DDoSPot detection no longer swallows other honeypots' logs (MedPot, Go-pot, Honeyaml). Their attackers were being tagged `possibly-spoofed` and dropped from the feed. DDoSPot now needs a `ddospot` folder or `"type": "ddospot"`.
- Timestamps are parsed the same way on Python 3.8-3.13 (compact `+0530` offsets, fractions of any length).
- With `--since`/`--until`, events without a timestamp are no longer counted as inside the window.
- Messages no longer say only Cowrie/Conpot are supported.

### Added
- `credentials.jsonl`: exact username/password values for wordlists (`credentials.csv` stays spreadsheet-safe).
- Warning when `--public` is used without `--anonymize-sensors`.
- Test suite (`tests/`), demo data (`samples/`), README.
