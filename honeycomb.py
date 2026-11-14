#!/usr/bin/env python3
"""
HONEYCOMB - combs through honeypot logs. Multi-sensor, offline, 30 honeypot types.

Point it at the folder your collection script fills, one child folder per sensor:

    honeypot-logs\\
        finance-us-east-1\\      cowrie.json, cowrie.json.2026-11-07, ... (.gz is fine)
        conpot-ps04\\            conpot.json* and/or conpot.log*
        med-nyc-1\\              medpot.log
        tpot-fra1\\              a copy of T-Pot's /data folder (cowrie/log, dionaea/log, ...)
        tpot-export\\            NDJSON exported from T-Pot's Elasticsearch (logstash-*)

Each child folder is one sensor; files are found recursively inside it and the
log type is detected per file (by folder name, file name, then by sniffing the first lines).
DDoSPot logs are only recognised in a folder named ddospot (as in T-Pot) or with
"type": "ddospot" in sensors.json - their records are too plain to identify on their own.

Supported: Cowrie, Conpot, MedPot, Dionaea, Honeytrap, Heralding, ADBHoney, Beelzebub,
Cisco ASA, Citrix ADC, DDoSPot, Dicompot, Elasticpot, Endlessh, Galah, Glutton, Go-pot,
H0neytr4p, Hellpot, Honeyaml, qeeqbox honeypots, IPPHoney, Log4Pot, Mailoney, Miniprint,
RDP honeypot, Redis honeypot, SentryPeer, Tanner/Snare, Wordpot - i.e. everything T-Pot
runs - plus T-Pot Elasticsearch exports, and any other JSON log that has a source IP and
a timestamp (parsed generically). T-Pot's Suricata, P0f, Fatt and NGINX logs are skipped:
they are sensors and the admin web UI, not attacker sessions.

MITRE ATT&CK: commands, logins, downloads, exploits and scans are mapped to ATT&CK (and
ATT&CK for ICS) techniques: shown as a matrix in the dashboard, listed per IOC, and exported
to STIX as kill_chain_phases plus attack-pattern objects linked by "indicates" relationships.

Geo / ASN (still offline): pass --geoip with a GeoLite2 / DB-IP Lite / IPinfo Lite .mmdb or a
DB-IP / IP2Location .csv[.gz] (repeatable, e.g. City + ASN), or drop the files in ~/.honeycomb/.
T-Pot Elasticsearch exports already carry geo and are used when no database is given.

Outputs (in --out, default .\\honeycomb-report):
    dashboard.html            overview + one tab per sensor + IOC browser (offline, no CDN)
    iocs\\master_iocs.csv      every shareable IOC with first/last seen, sensors, tags, confidence
    iocs\\master_iocs.json     same, JSON
    iocs\\stix2_bundle.json    STIX 2.1 indicators (stable IDs + proper versioning) for TAXII
    iocs\\ipv4.txt, ipv6.txt, urls.txt, domains.txt, sha256.txt   plain blocklists
    iocs\\hassh.txt, ssh_keys.txt   SSH client and attacker-key fingerprints (context, not in STIX)
    credentials.csv           attempted username/password pairs (not IOCs; research data).
                              Spreadsheet-safe: values starting with = + - @ get a leading '
    credentials.jsonl         the same pairs byte-for-byte (use this for wordlists)

Usage:
    python honeycomb.py C:\\honeypot-logs
    python honeycomb.py C:\\honeypot-logs --out C:\\reports\\today --since 2026-11-01
    python honeycomb.py C:\\honeypot-logs --exclude 203.0.113.7 --anonymize-sensors
    python honeycomb.py C:\\honeypot-logs --public --anonymize-sensors   # dashboard safe to share
    python3 honeycomb.py ~/honeypot-logs --days 7                       # Linux / macOS
    python3 honeycomb.py ~/honeypot-logs --min-confidence medium --anonymize-sensors   # public feed

What is kept out of the shareable exports:
    * your sensors' own IPs (learned from the logs, plus --exclude), including inside URLs
    * private / reserved addresses, and URLs or domains that point at them
    * well-known benign services (IP-check sites, package mirrors, big CDNs); add your own
      with --allowlist FILE or "allowlist" in sensors.json (one domain per line, subdomains match)
    * domains of shared hosting (GitHub, Pastebin, S3...) - the full URL is still exported
    * research scanners: by ASN name (needs --geoip) and by the ranges in scanners.txt / --scanners

State file (default ~/.honeycomb/state.json, change with --state, disable with --no-state)
remembers every IOC between runs - one file for all runs, so a new folder per log pull still
continues the same feed. That keeps first_seen historic when you use
--days, gives STIX objects a fixed `created` and a new `modified` only when they change, and
keeps --anonymize-sensors names stable. It contains a secret salt: don't publish it.

Optional <root>\\sensors.json:
    {
      "sensors": {
        "finance-us-east-1": {"label": "Cowrie US-East", "public_name": "sensor-us"},
        "cowrie-blr1":       {"label": "Cowrie Bangalore", "public_name": "sensor-in"},
        "conpot-ps04":       {"label": "Conpot ICS", "type": "conpot"}
      },
      "exclude": ["198.51.100.10", "192.0.2.0/24"],
      "allowlist": ["example-monitoring.com"]
    }

Python 3.8+, standard library only.
"""

import argparse
import ast
import base64
import binascii
import csv
import gzip
import hashlib
import ipaddress
import json
import os
import re
import secrets
import sys
import uuid
import zlib
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import unquote_plus, urlsplit

VERSION = "1.3.4"
TOOL = "HONEYCOMB"
TOP_N = 15

# --------------------------------------------------------------------------- #
# Banner
# --------------------------------------------------------------------------- #

BANNER = r"""
     __    __    __
  __/  \__/  \__/  \__    _   _  ___  _   _ _______   ______ ___  __  __ ____
 /  \__/  \__/  \__/  \  | | | |/ _ \| \ | | ____\ \ / / ___/ _ \|  \/  | __ )
 \__/  \__/  \__/  \__/  | |_| | | | |  \| |  _|  \ V / |  | | | | |\/| |  _ \
 /  \__/  \__/  \__/  \  |  _  | |_| | |\  | |___  | || |__| |_| | |  | | |_) |
 \__/  \__/  \__/  \__/  |_| |_|\___/|_| \_|_____| |_| \____\___/|_|  |_|____/
    \__/  \__/  \__/
"""
COMB_W = 24  # width of the honeycomb part of each banner line


def _enable_ansi():
    """Turn on ANSI colours in the Windows console (no-op elsewhere)."""
    if os.name != "nt":
        return True
    try:
        import ctypes
        k32 = ctypes.windll.kernel32
        handle = k32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if not k32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(k32.SetConsoleMode(handle, mode.value | 0x0004))  # VIRTUAL_TERMINAL_PROCESSING
    except Exception:
        return False


def print_banner(color):
    amber, gold, dim, reset = ("\033[38;5;208m", "\033[1;38;5;220m", "\033[2m", "\033[0m") if color \
        else ("", "", "", "")
    lines = BANNER.strip("\n").splitlines()
    for line in lines:
        print(amber + line[:COMB_W] + reset + gold + line[COMB_W:] + reset)
    print("%s   combing through honeypot logs  ::  v%s  ::  30 honeypot types%s\n" % (dim, VERSION, reset))

# --------------------------------------------------------------------------- #
# File discovery & reading
# --------------------------------------------------------------------------- #

COWRIE_JSON_NAME = re.compile(r"^cowrie\.json([._-].*)?$", re.I)
COWRIE_TEXT_NAME = re.compile(r"^cowrie\.log([._-].*)?$", re.I)
CONPOT_JSON_NAME = re.compile(r"^conpot[^/\\]*\.json([._-].*)?$", re.I)
CONPOT_TEXT_NAME = re.compile(r"^conpot[^/\\]*\.log([._-].*)?$", re.I)
SNIFF_EXT = {".json", ".jsonl", ".log", ".txt", ".gz", ""}
SNIFF_BYTES = 64 * 1024
# Cowrie keeps captured malware in downloads/ (files named by SHA-256, no extension) and
# session recordings in tty/. Never open those as logs.
SKIP_DIRS = {"downloads", "dl", "tty", "ttylog", "quarantine", "__pycache__"}
READ_ERRORS = (OSError, EOFError, zlib.error)


def open_text(path):
    if path.suffix.lower() == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def _json_kind(o, hint):
    """Which parser handles this JSON record? (hint = adapter suggested by the folder name)"""
    if not isinstance(o, dict):
        return None
    if is_tpot_es(o):
        return "tpot-es"
    if str(o.get("eventid", "")).startswith("cowrie."):
        return "cowrie"
    if "data_type" in o and "src_ip" in o:
        return "conpot-json"
    matches = []
    for k in JSON_ORDER:
        if ADAPTERS[k].hint_only and k != hint:
            continue
        try:
            if ADAPTERS[k].detect(o):
                matches.append(k)
        except (AttributeError, TypeError, ValueError):
            continue
    if hint and hint in matches:
        return hint
    specific = [k for k in matches if k != "generic"]
    if specific:
        return specific[0]
    if hint in ADAPTERS and ADAPTERS[hint].fmt == "json" and clean_ip(first(o, *SRC_KEYS)):
        return hint
    return "generic" if matches else None


def _pyrepr(line):
    """Parse a python-dict style line ({'a': 1}) safely; None if it isn't one."""
    if not line.startswith("{'") or len(line) > 200000:
        return None
    try:
        o = ast.literal_eval(line)
    except (ValueError, SyntaxError, MemoryError, RecursionError):
        return None
    return o if isinstance(o, dict) else None


def sniff(path, hint=None):
    """Work out the log format from the first 64 KB of a file. Returns a kind or None."""
    try:
        with open_text(path) as fh:
            head = fh.read(SNIFF_BYTES)
    except READ_ERRORS:
        return None
    if "\x00" in head:
        return None  # binary
    votes = Counter()
    for line in head.splitlines()[:60]:
        line = line.strip()
        if not line:
            continue
        if line.startswith("{"):
            try:
                o = json.loads(line)
            except ValueError:
                o = _pyrepr(line)
                if o is not None and ADAPTERS["ciscoasa"].detect(o):
                    votes["ciscoasa"] += 1
                continue
            k = _json_kind(o, hint)
            if k:
                votes[k] += 1
            continue
        for k in TEXT_ORDER:
            if ADAPTERS[k].detect(line):
                votes[k] += 1
                break
        else:
            if re.search(r"conpot|S7|Modbus|BACnet|ENIP|IPMI|SNMP", line) and TS_RE.search(line):
                votes["conpot-text"] += 1
    if not votes:
        return None
    specific = [k for k, _ in votes.most_common() if k != "generic"]
    return specific[0] if specific else "generic"


def classify(path, hint=None):
    name = path.name
    if COWRIE_TEXT_NAME.match(name):
        return None  # Cowrie's text log duplicates the JSON log
    if COWRIE_JSON_NAME.match(name):
        return "cowrie"
    if CONPOT_JSON_NAME.match(name):
        return "conpot-json"
    if CONPOT_TEXT_NAME.match(name):
        return "conpot-text"
    ext = path.suffix.lower()
    if ext in SNIFF_EXT or ext == ".csv" or re.search(r"\.json|\.log|\.csv", name, re.I):
        return sniff(path, hint)
    return None


# --------------------------------------------------------------------------- #
# Parsing helpers
# --------------------------------------------------------------------------- #

TS_RE = re.compile(r"(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[,.]\d+)?)")
IPV4_RE = re.compile(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?![\d.])")
URL_RE = re.compile(r"\b((?:https?|ftp|tftp|ldaps?|rmi|iiop|corba|nis|nds)://[^\s'\"`;|<>(){}\\]+)", re.I)
# Shell download/execute idioms inside a network payload (not a shell session) = exploit attempt
PAYLOAD_EXEC_RE = re.compile(r"(?:\b(?:wget|curl|tftp|ftpget)\b.{0,80}(?:https?|tftp|ftp)://|"
                             r"\bbusybox\s+\w+|/bin/(?:ba)?sh\b|\bchmod\s+[+0-7]|\|\s*(?:ba)?sh\b)", re.I | re.S)
CONPOT_HTTP_REQ_RE = re.compile(r"\b([A-Z]{3,10}) request from \(.*?\):\s*\(?\s*['\"]([^'\"]*)['\"]")
CONPOT_RESPONSE_RE = re.compile(r"\bresponse to \(")
CONPOT_SESSION_RE = re.compile(r"\(?\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b\)?")
CONPOT_OWN_IP_RE = re.compile(r"Fetched\s+(\S+?)\s+as\s+external\s+ip", re.I)

CONPOT_PROTOS = [
    ("s7", "s7comm"), ("modbus", "modbus"), ("bacnet", "bacnet"), ("enip", "enip"),
    ("ipmi", "ipmi"), ("snmp", "snmp"), ("tftp", "tftp"), ("ftp", "ftp"),
    ("kamstrup", "kamstrup"), ("guardian", "guardian_ast"), ("http", "http"),
]

# Real ICS/OT protocols. Conpot also serves HTTP/FTP/TFTP/SSH, and generic web scanners hit
# those constantly - that's not ICS reconnaissance, so it doesn't earn the ics-scan tag.
ICS_PROTOCOLS = {"s7comm", "modbus", "bacnet", "enip", "ipmi", "kamstrup", "kamstrup_protocol",
                 "kamstrup_management_protocol", "guardian_ast", "iec104", "dnp3", "s7", "IEC104"}
# SHA-256 of an empty file: Cowrie logs it whenever an attacker creates/uploads a zero-byte
# file. It matches every empty file on earth, so it's never an IOC.
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
URL_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.I)
# Internet-wide research scanners, matched on the ASN organisation name. Their traffic is
# real but benign, and feed consumers don't want them on a blocklist.
RESEARCH_SCANNER_RE = re.compile(
    r"\b(censys|onyphe|shadowserver|shodan|stretchoid|binaryedge|modat|driftnet|alpha strike labs|"
    r"leakix|criminal ?ip|ai spera|recyber|rapid7|bitsight|internet[- ]measurement|cortex xpanse|"
    r"palo alto networks|netscout|securitytrails|academy for internet research|ipip\.net)\b", re.I)

CMD_CATEGORIES = [
    ("system/kernel enum", re.compile(
        r"\buname\b|/proc/(cpuinfo|meminfo|version|mounts)|\blscpu\b|\bnproc\b|\bfree\s+-|"
        r"/etc/(issue|os-release|lsb-release)|\bdmidecode\b|\blsblk\b|\bdf\s+-", re.I)),
    ("user/host recon", re.compile(
        r"\bwhoami\b|(^|[;&|\s])id(?=[\s;&|]|$)|(^|[;&|\s])w(?=[\s;&|]|$)|\blast\b|/etc/passwd|\bhostname\b|"
        r"\bifconfig\b|\bip\s+(a|addr|route)\b|\bnetstat\b|\bss\s+-|\bps\s+(aux|-ef)|\btop\b", re.I)),
    ("privilege escalation", re.compile(
        r"\bsudo\b|(^|[;&|\s])su(?=[\s;&|]|$)|\bpkexec\b|/etc/(shadow|sudoers)|chmod\s+(u\+s|[0-7]?[4-7][0-7]{3}\b)|"
        r"\bsetuid\b|\bgetcap\b|find\s+/.*-perm", re.I)),
    ("persistence", re.compile(
        r"authorized_keys|\bcrontab\b|/etc/cron|systemctl\s+enable|/etc/rc\.local|\.bashrc|"
        r"\.profile\b|/etc/init\.d|\bchattr\b|useradd|adduser", re.I)),
    ("credential change", re.compile(r"\bchpasswd\b|(^|[;&|\s])passwd\b|\busermod\b", re.I)),
    ("download / stage", re.compile(
        r"\bwget\b|\bcurl\b|\btftp\b|\bftpget\b|\bscp\b|\bnc\s+|\bbusybox\s+(wget|tftp)|"
        r"chmod\s+\+x|chmod\s+777", re.I)),
    ("cryptomining", re.compile(
        r"xmrig|stratum\+tcp|minerd|cpuminer|c3pool|nanopool|moneroocean|--donate-level|nicehash", re.I)),
    # Only genuine anti-forensics / security-control tampering. "> /dev/null 2>&1" is in almost
    # every bot one-liner and says nothing about intent, so it is no longer counted.
    ("defense evasion", re.compile(
        r"history\s+-c|unset\s+HISTFILE|HISTFILE=/dev/null|export\s+HISTFILE=|HISTSIZE=0|"
        r"rm\s+-r?f+\s+/var/log|>\s*/var/log/\S+|\bshred\b|iptables\s+-F|ufw\s+disable|setenforce\s+0|"
        r"systemctl\s+(stop|disable)\s+(firewalld|apparmor|auditd|aliyun)", re.I)),
    # Miners and botnets killing each other off - common, but not evasion of *us*.
    ("kill competitors", re.compile(r"\bpkill\b|\bkillall\b|kill\s+-9", re.I)),
]

# Services bots call to check connectivity / learn their IP, package mirrors and big
# platforms. Neither the domain nor URLs on it are exported. Subdomains match.
BENIGN_DOMAINS = {
    "ipinfo.io", "ifconfig.me", "ifconfig.co", "icanhazip.com", "ipify.org", "ip-api.com",
    "ipecho.net", "ident.me", "wtfismyip.com", "myip.dnsomatic.com", "checkip.dyndns.org",
    "checkip.amazonaws.com", "httpbin.org", "myexternalip.com", "ipapi.co", "api.myip.com",
    "google.com", "gstatic.com", "googleapis.com", "cloudflare.com", "microsoft.com", "apple.com",
    "baidu.com", "bing.com", "yahoo.com", "example.com", "example.org", "example.net",
    "ubuntu.com", "debian.org", "centos.org", "fedoraproject.org", "alpinelinux.org",
    "archlinux.org", "pypi.org", "pythonhosted.org", "npmjs.org", "npmjs.com",
}
# Shared hosting abused for payloads: the domain itself would be a terrible blocklist entry,
# but the full URL is a good IOC, so URLs are still exported.
SHARED_HOSTING = {
    "github.com", "githubusercontent.com", "gitlab.com", "bitbucket.org", "pastebin.com",
    "paste.ee", "transfer.sh", "dropbox.com", "dropboxusercontent.com", "discordapp.com",
    "discordapp.net", "discord.com", "amazonaws.com", "cloudfront.net", "azureedge.net",
    "blob.core.windows.net", "googleusercontent.com",
    "sourceforge.net", "mediafire.com", "anonfiles.com",
    # out-of-band callback services used by both attackers and research scanners (Log4Shell etc.)
    "oast.fun", "oast.pro", "oast.live", "oast.site", "oast.online", "oast.me", "interact.sh",
    "interactsh.com", "dnslog.cn", "ceye.io", "burpcollaborator.net", "oastify.com", "canarytokens.com",
}
# Dynamic DNS / tunnel services: every subdomain belongs to one customer, so
# "phubotnet.duckdns.org" is a perfect IOC even though "duckdns.org" itself must never be blocked.
DYNAMIC_DNS = {
    "duckdns.org", "no-ip.org", "no-ip.com", "no-ip.biz", "no-ip.info", "noip.me", "ddns.net",
    "hopto.org", "zapto.org", "sytes.net", "servebeer.com", "serveftp.com", "myftp.org",
    "myftp.biz", "redirectme.net", "servehttp.com", "dynu.net", "dynu.com", "dyndns.org",
    "dyndns.info", "ddnsfree.com", "ddns.me", "freeddns.org", "mooo.com", "chickenkiller.com",
    "ngrok.io", "ngrok-free.app", "ngrok.app", "trycloudflare.com", "serveo.net", "loca.lt",
    "portmap.io", "portmap.host", "dnsabr.com", "linkpc.net", "giize.com", "gleeze.com",
}
# exploit-payload: a URL inside a network request that also tries to download and run it
# ("GET /setup.cgi?cmd=wget+http://x/Mozi.m+-O+/tmp/a;sh+/tmp/a") - a payload, like a Cowrie wget
FETCH_TAGS = {"downloaded", "download-failed", "exploit-callback", "exploit-payload"}
# download-url: a URL given to wget/curl/tftp/ftpget in a shell command (the staging URL itself)
FETCH_TAGS = FETCH_TAGS | {"download-url"}
DL_VERB_RE = re.compile(r"\b(?:wget|curl|tftp|ftpget|lwp-download|aria2c|fetch)\b", re.I)
CMD_SEP_RE = re.compile(r"\|\||&&|[;|\n]|&(?=\s|$)")
# URLs pulled out of network traffic (not shell commands) are URL-decoded first
DECODE_TAGS = {"seen-in-ics-request", "seen-in-payload", "exploit-callback", "exploit-payload"}


def is_exploit(text):
    """Does a network request/payload try to download and run something? (URL-decoded first)"""
    if "%" in text or "+" in text:
        text = unquote_plus(text)
    return bool(PAYLOAD_EXEC_RE.search(text))


def domain_in(host, domains):
    host = host.lower().rstrip(".")
    return any(host == d or host.endswith("." + d) for d in domains)


# Date and time, any of - . / between date parts ("2018.09.09 17:20:49" is MedPot), optional
# fraction of any length, optional zone: Z, UTC, +05, +0530, +05:30 (and the odd "+00:00Z").
# Parsed by hand so Python 3.8-3.10 (whose fromisoformat is strict) gets the same answer as 3.11+.
TS_PARSE_RE = re.compile(
    r"^(\d{4})[-./](\d{1,2})[-./](\d{1,2})[T ](\d{1,2}):(\d{2})(?::(\d{2}))?(?:[.,](\d+))?\s*"
    r"(Z|UTC|GMT|[+-]\d{2}(?::?\d{2})?)?Z?$", re.I)


def parse_ts(value):
    """Timestamp string -> aware UTC datetime, or None. Strings without a zone are taken as UTC."""
    if not value:
        return None
    s = str(value).strip()
    m = TS_PARSE_RE.match(s)
    if m:
        y, mo, d, h, mi, sec, frac, zone = m.groups()
        tz = timezone.utc
        if zone and zone[0] in "+-":
            digits = zone[1:].replace(":", "")
            off = timedelta(hours=int(digits[:2]), minutes=int(digits[2:4] or 0))
            tz = timezone(off if zone[0] == "+" else -off)
        try:
            dt = datetime(int(y), int(mo), int(d), int(h), int(mi), int(sec or 0),
                          int((frac or "0")[:6].ljust(6, "0")), tzinfo=tz)
        except ValueError:
            return None
        return dt.astimezone(timezone.utc)
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ") if dt else ""


def short(s, n=160):
    s = " ".join(str(s).split())
    return s if len(s) <= n else s[: n - 1] + "\u2026"


class IPFilter:
    def __init__(self, nets, include_private):
        self.nets = nets
        self.include_private = include_private
        self.cache = {}

    def blocked(self, ip):
        if ip in self.cache:
            return self.cache[ip]
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            self.cache[ip] = True
            return True
        res = (not self.include_private and not addr.is_global) or any(addr in n for n in self.nets)
        self.cache[ip] = res
        return res

    def kind(self, ip):
        """For hosts inside URLs: 'own-sensor' if --exclude'd, 'private-host' if not routable."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        if any(addr in n for n in self.nets):
            return "own-sensor"
        if not addr.is_global:
            return "private-host"
        return None


class ScannerList:
    """Research-scanner ranges (Censys, Shodan, Xpanse...). Sorted, merged intervals + bisect, so
    a list of thousands of CIDRs (e.g. OpenFilters/internet-scanners) stays fast."""

    def __init__(self):
        self.ranges = {4: [], 6: []}
        self.sources, self.count, self.bad = [], 0, 0
        self._idx = None

    def load(self, lines, source):
        n = 0
        for line in lines:
            tok = re.split(r"[\s,;]", str(line).split("#", 1)[0].strip(), maxsplit=1)[0]
            if not tok:
                continue
            try:
                net = ipaddress.ip_network(tok, strict=False)
            except ValueError:
                self.bad += 1
                continue
            self.ranges[net.version].append((int(net.network_address), int(net.broadcast_address)))
            n += 1
        if n:
            self.sources.append(source)
            self.count += n
            self._idx = None

    def _build(self):
        import bisect
        self._bisect = bisect
        self._idx = {}
        for v, rs in self.ranges.items():
            merged = []
            for a, b in sorted(rs):
                if merged and a <= merged[-1][1] + 1:
                    merged[-1][1] = max(merged[-1][1], b)
                else:
                    merged.append([a, b])
            self._idx[v] = ([m[0] for m in merged], merged)

    def contains(self, ip):
        if not self.count:
            return False
        if self._idx is None:
            self._build()
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        starts, rs = self._idx[a.version]
        i = self._bisect.bisect_right(starts, int(a)) - 1
        return i >= 0 and rs[i][0] <= int(a) <= rs[i][1]


def valid_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


# --------------------------------------------------------------------------- #
# Honeypot adapters
# --------------------------------------------------------------------------- #
# Cowrie and Conpot have dedicated handlers (Analyzer.cowrie / conpot_json / conpot_text).
# Every other honeypot is turned into *normalised events* by a small adapter below and fed
# through Analyzer.generic(). An event is a plain dict:
#
#   hp        honeypot name                     ts        datetime (UTC)
#   src       attacker IP                       dst_ip    our own IP, if the log has it
#   dst_port  port that was hit                 service   protocol / service label
#   session   session id - first sighting counts as a session (or set new_session=True)
#   label     short event name for the "Event types" chart
#   user, password, ok    a login attempt
#   command   something run in an emulated shell (scored like Cowrie commands)
#   request   protocol request summary (HTTP line, SMTP verb, SIP method, HL7 message...)
#   ua        client / user agent               duration  session length in seconds
#   text      payload to scan for URLs (text_tag says why it was seen)
#   url       a URL that was fetched (url_tag)  sha256    a captured file (hash_tag)
#   tags      extra tags for the attacker IP
#
# Field names come from each project's own logger and from T-Pot's Logstash config, so the
# same adapter also understands records exported from T-Pot's Elasticsearch.

SRC_KEYS = ("src_ip", "source_ip", "srcIP", "client_ip", "client", "REMOTE_ADDR", "remote_ip",
            "remote_host", "peer.ip", "attack_connection.remote_ip", "addr", "sourceIp", "IP")
DIP_KEYS = ("dst_ip", "dest_ip", "destination_ip", "local_ip", "attack_connection.local_ip",
            "destinationIp")
DPORT_KEYS = ("dst_port", "dest_port", "destination_port", "server_port", "local_port",
              "attack_connection.local_port", "destinationPort")
TS_KEYS = ("timestamp", "@timestamp", "time", "asctime", "event_timestamp", "eventTime", "ts",
           "DateTime", "date")
PATH_KEYS = ("path", "url", "request_uri", "requestURI", "URL", "uri", "request.requestURI",
             "httpRequest.request", "httpRequest.requestURI", "http.url")
METHOD_KEYS = ("method", "request_method", "requestMethod", "request.method", "httpRequest.method",
               "http.http_method")
UA_KEYS = ("user_agent", "user-agent", "userAgent", "USERAGENT", "http_user_agent",
           "request.userAgent", "httpRequest.userAgent", "headers.user-agent", "headers.User-Agent")


def dig(o, path, default=None):
    """o['a']['b'] for 'a.b'; a flattened 'a.b' key (as Logstash/ewsposter produce) also works."""
    if not isinstance(o, dict):
        return default
    if path in o:
        return o[path]
    cur = o
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


def first(o, *paths):
    for p in paths:
        v = dig(o, p)
        if v not in (None, "", [], {}):
            return v
    return None


def aslist(v):
    if v is None:
        return []
    return list(v) if isinstance(v, (list, tuple)) else [v]


def clean_ip(v):
    """'::ffff:1.2.3.4', '1.2.3.4:5060', '[2001:db8::1]:80' -> bare IP; '' if it isn't one."""
    if v in (None, ""):
        return ""
    s = str(v).strip()
    if s.lower().startswith("::ffff:") and "." in s:
        s = s[7:]
    if valid_ip(s):
        return s
    m = re.match(r"^\[([0-9a-fA-F:.]+)\]:\d+$", s) or re.match(r"^((?:\d{1,3}\.){3}\d{1,3}):\d+$", s)
    if m and valid_ip(m.group(1)):
        return clean_ip(m.group(1))
    return ""


def to_port(v):
    try:
        p = int(str(v).rsplit(":", 1)[-1])
    except (TypeError, ValueError):
        return None
    return p if 0 < p < 65536 else None


def ts_any(o, *keys):
    for k in keys or TS_KEYS:
        v = dig(o, k)
        if v in (None, ""):
            continue
        if isinstance(v, (int, float)) or re.fullmatch(r"\d{9,13}(\.\d+)?", str(v)):
            f = float(v)
            if f > 1e11:  # milliseconds
                f /= 1000.0
            try:
                return datetime.fromtimestamp(f, timezone.utc)
            except (OverflowError, OSError, ValueError):
                continue
        dt = parse_ts(v)
        if dt:
            return dt
    return None


def printable(data, limit=4096):
    """bytes -> readable text (non-printables become '.')."""
    if isinstance(data, str):
        return data[:limit]
    txt = bytes(data[:limit]).decode("latin-1")
    return "".join(c if c in "\r\n\t" or 32 <= ord(c) < 127 else "." for c in txt)


def from_hex(s):
    try:
        return binascii.unhexlify(re.sub(r"[^0-9a-fA-F]", "", str(s))[:16384])
    except (binascii.Error, ValueError):
        return b""


def from_b64(s):
    try:
        return base64.b64decode(str(s)[:22000], validate=False)
    except (binascii.Error, ValueError):
        return b""


def first_line(text, n=140):
    for line in str(text).splitlines():
        if line.strip():
            return short(line, n)
    return ""


def http_request(o):
    m = first(o, *METHOD_KEYS)
    p = first(o, *PATH_KEYS)
    if p is None:
        return None
    return ("%s %s" % (m, p)) if isinstance(m, str) and m else str(p)


def event(hp, o, service=None, port=None, **kw):
    """Normalised event with the fields every honeypot shares; adapter-specific ones in kw."""
    ev = {"hp": hp, "ts": ts_any(o, *TS_KEYS), "src": clean_ip(first(o, *SRC_KEYS)),
          "dst_ip": clean_ip(first(o, *DIP_KEYS)), "dst_port": to_port(first(o, *DPORT_KEYS)) or port,
          "service": service or hp}
    ua = first(o, *UA_KEYS)
    if isinstance(ua, str):
        ev["ua"] = ua
    for k, v in kw.items():
        if v not in (None, "", [], ()):
            ev[k] = v
    return ev


class Adapter:
    def __init__(self, name, parse, detect, dirs=(), fmt="json", hp=None, hint_only=False):
        self.name = name          # kind id used internally
        self.hp = hp or name      # honeypot name shown to the user
        self.parse = parse        # parse(record, ctx) -> event | [events] | None
        self.detect = detect      # detect(record) -> bool, used on the first lines of a file
        self.dirs = set(dirs) | {self.hp}  # folder names that hint at this honeypot (T-Pot layout)
        self.fmt = fmt            # json | text | csv | pyrepr
        # hint_only: the record format is too plain to recognise on its own (DDoSPot is just
        # time + src_ip), so only use this adapter when the folder name or sensors.json says so.
        self.hint_only = hint_only


ADAPTERS = {}


def adapter(name, detect, dirs=(), fmt="json", hp=None, hint_only=False):
    def deco(fn):
        ADAPTERS[name] = Adapter(name, fn, detect, dirs, fmt, hp, hint_only)
        return fn
    return deco


def _eid(o, prefix):
    return str(o.get("eventid", "")).startswith(prefix)


# ---- ADBHoney (Android Debug Bridge) -------------------------------------- #
@adapter("adbhoney", lambda o: _eid(o, "adbhoney."))
def p_adbhoney(o, ctx):
    eid = str(o.get("eventid", ""))
    ev = event("adbhoney", o, "adb", 5555, session=o.get("session"), label=eid.split(".", 1)[-1])
    if "command" in eid:
        ev["command"] = str(o.get("input", ""))
    elif "file" in eid:
        ev["sha256"], ev["hash_tag"] = str(o.get("shasum", "")).lower(), "uploaded"
    return ev


# ---- Beelzebub (LLM-backed SSH/HTTP/TCP) ---------------------------------- #
def d_beelzebub(o):
    if isinstance(o.get("event"), dict) and ("RemoteAddr" in o["event"] or "Protocol" in o["event"]):
        return True
    msg = str(o.get("message") or o.get("msg") or "")
    return "session" in o and bool(re.match(r"(New |End )?(SSH|HTTP|TCP)\b", msg))


@adapter("beelzebub", d_beelzebub)
def p_beelzebub(o, ctx):
    e = o.get("event") if isinstance(o.get("event"), dict) else None
    if e is not None:  # native Beelzebub log line
        proto = str(e.get("Protocol") or "tcp").lower()
        ev = event("beelzebub", {"timestamp": e.get("DateTime") or o.get("time"),
                                 "src_ip": e.get("SourceIp") or e.get("RemoteAddr"),
                                 "dest_port": e.get("Port")}, proto,
                   session=e.get("SessionID") or e.get("ID"), label=short(e.get("Msg") or proto, 60),
                   ua=e.get("UserAgent"))
        user, pw, cmd = e.get("User"), e.get("Password"), e.get("Command")
        if e.get("HTTPMethod") or e.get("RequestURI"):
            ev["request"] = "%s %s" % (e.get("HTTPMethod", ""), e.get("RequestURI", ""))
            ev["text"] = "%s %s" % (e.get("RequestURI", ""), e.get("Body", ""))
    else:  # T-Pot's flattened format
        proto = str(o.get("protocol") or "ssh").lower()
        ev = event("beelzebub", o, proto, session=o.get("session"),
                   label=short(o.get("message") or o.get("msg") or proto, 60))
        user, pw, cmd = o.get("username"), o.get("password"), o.get("input")
        if http_request(o):
            ev["request"] = http_request(o)
    if user or pw:
        ev.update(user=str(user or ""), password=str(pw or ""), ok=False)
    if cmd:
        ev["command"] = str(cmd)
    return ev


# ---- Cisco ASA honeypot (python-dict style lines) ------------------------- #
@adapter("ciscoasa", lambda o: isinstance(o, dict) and ("payload_printable" in o or "payload" in o),
         fmt="pyrepr")
def p_ciscoasa(o, ctx):
    payload = str(o.get("payload_printable") or o.get("payload") or "")
    return event("ciscoasa", o, "cisco-asa", 8443, new_session=True, label="request",
                 request=first_line(payload) or None, text=payload or None)


# ---- Citrix ADC honeypot (CVE-2019-19781) --------------------------------- #
CITRIX_RE = re.compile(r"^\((\S+?):(\d+)\):\s*(.*)$", re.S)


@adapter("citrixhoneypot", lambda o: "asctime" in o and bool(CITRIX_RE.match(str(o.get("message", "")))),
         dirs=("citrix",))
def p_citrix(o, ctx):
    m = CITRIX_RE.match(str(o.get("message", "")))
    if not m:
        return None
    rest = m.group(3)
    tags = ["web-attack"] if re.search(r"travers|\.\./|smb\.conf|newbm\.pl|/vpns/", rest, re.I) else []
    return event("citrixhoneypot", {"timestamp": o.get("asctime"), "src_ip": m.group(1)}, "citrix-adc",
                 443, new_session=True, label=short(o.get("levelname") or "request", 30),
                 request=short(rest, 140), text=rest, tags=tags)


# ---- DDoSPot (chargen / dns / ntp / ssdp reflectors) ---------------------- #
DDOSPOT_SVC = {"chargen": ("chargen", 19), "dns": ("dns", 53), "ntp": ("ntp", 123),
               "ssdp": ("ssdp", 1900)}


@adapter("ddospot", lambda o: "time" in o and "src_ip" in o and not ("eventid" in o or "action" in o),
         hint_only=True)
def p_ddospot(o, ctx):
    stem = Path(ctx.get("path", "")).name.lower()
    svc, port = next((v for k, v in DDOSPOT_SVC.items() if stem.startswith(k)), ("udp", None))
    req = first(o, "dns_name", "query", "request", "data")
    # Reflection honeypots mostly see *spoofed* victim addresses - never treat them as attackers.
    return event("ddospot", o, svc, port, new_session=True, label=svc + " request",
                 request=short(req, 140) if req else None, tags=["spoofable-udp"])


# ---- Dicompot (DICOM medical imaging) ------------------------------------- #
@adapter("dicompot", lambda o: "IP" in o and ("AETitle" in o or "Command" in o or "ID" in o))
def p_dicompot(o, ctx):
    req = " ".join(str(x) for x in (o.get("Command"), o.get("AETitle")) if x)
    return event("dicompot", o, "dicom", 11112, session=o.get("ID"),
                 label=short(o.get("Command") or o.get("Status") or "event", 40),
                 request=req or None, tags=["medical-scan"])


# ---- Dionaea (SMB, MSSQL, MySQL, FTP, SIP, ... ) -------------------------- #
DIONAEA_SVC = {"smbd": "smb", "httpd": "http", "ftpd": "ftp", "mssqld": "mssql", "mysqld": "mysql",
               "sipd": "sip", "epmapper": "msrpc", "mqttd": "mqtt", "memcache": "memcached",
               "tftpd": "tftp", "pptpd": "pptp", "upnpd": "upnp", "mongod": "mongodb",
               "printerd": "printer"}


@adapter("dionaea", lambda o: isinstance(o.get("connection"), dict) and "src_ip" in o)
def p_dionaea(o, ctx):
    conn = o.get("connection") or {}
    proto = str(conn.get("protocol") or conn.get("transport") or "unknown")
    svc = DIONAEA_SVC.get(proto, proto)
    base = event("dionaea", o, svc, new_session=True, label=svc + " connection")
    out = [base]
    common = {k: base[k] for k in ("hp", "ts", "src", "dst_port", "service")}
    creds = o.get("credentials") or {}
    users, pws = aslist(creds.get("username")), aslist(creds.get("password"))
    if not users and (o.get("username") or o.get("password")):  # Elasticsearch export
        users, pws = aslist(o.get("username")), aslist(o.get("password"))
    for i in range(max(len(users), len(pws))):
        out.append(dict(common, label=svc + " login", ok=False,
                        user=str(users[i] if i < len(users) else ""),
                        password=str(pws[i] if i < len(pws) else "")))
    cmds = aslist(dig(o, "ftp.commands.command"))
    args = aslist(dig(o, "ftp.commands.arguments"))
    for i, c in enumerate(cmds):
        a = args[i] if i < len(args) else ""
        out.append(dict(common, label="ftp command", request=("%s %s" % (c, a)).strip(), text=str(a)))
    for c in aslist(dig(o, "mysql.commands")) + aslist(dig(o, "mssql.commands")):
        out.append(dict(common, label=svc + " query", request=short(c, 140), text=str(c)))
    return out


# ---- Elasticpot (Elasticsearch) ------------------------------------------- #
@adapter("elasticpot", lambda o: _eid(o, "elasticpot."))
def p_elasticpot(o, ctx):
    eid = str(o.get("eventid", ""))
    req = "%s %s" % (o.get("request", "") or o.get("request_method", ""), o.get("url", "") or dig(o, "http.url") or "")
    return event("elasticpot", o, "elasticsearch", 9200, new_session=True, label=eid.split(".", 1)[-1],
                 request=req.strip() or None, text=str(o.get("payload") or "") or None,
                 tags=["web-attack"] if eid.endswith("attack") else [])


# ---- Endlessh (SSH tarpit, text log) -------------------------------------- #
ENDLESSH_RE = re.compile(r"^(\S+)\s+(ACCEPT|CLOSE)\s+host=(\S+)\s+port=(\d+)(?:.*?\btime=([\d.]+))?")


@adapter("endlessh", lambda line: bool(ENDLESSH_RE.match(line)), fmt="text")
def p_endlessh(line, ctx):
    m = ENDLESSH_RE.match(line)
    if not m:
        return None
    ts, what, host, sport, dur = m.groups()
    ev = event("endlessh", {"timestamp": ts, "src_ip": host}, "ssh-tarpit", 22, label=what.lower())
    if what == "ACCEPT":
        ev["new_session"] = True
    elif dur:
        ev["duration"] = float(dur)
    return ev


# ---- Galah (LLM web honeypot) --------------------------------------------- #
def d_galah(o):
    return isinstance(o.get("httpRequest"), dict) or "request.requestURI" in o or \
        (isinstance(o.get("request"), dict) and "requestURI" in o["request"])


@adapter("galah", d_galah)
def p_galah(o, ctx):
    return event("galah", o, "http", session=o.get("session") or dig(o, "httpRequest.sessionID"),
                 new_session=True, label=short(o.get("msg") or "request", 40),
                 request=http_request(o), text=str(first(o, *PATH_KEYS) or "") or None)


# ---- Glutton (catch-all TCP/UDP) ------------------------------------------ #
@adapter("glutton", lambda o: "payload_hex" in o or ("handler" in o and "src_ip" in o))
def p_glutton(o, ctx):
    if not o.get("src_ip"):
        return None
    payload = printable(from_hex(o.get("payload_hex", ""))) if o.get("payload_hex") else ""
    svc = str(o.get("handler") or "tcp").lower()
    return event("glutton", o, svc, session="%s:%s" % (o.get("src_ip"), o.get("src_port")),
                 label=short(o.get("msg") or svc, 40), request=first_line(payload) or None,
                 text=payload or None)


# ---- Go-pot (HTTP tarpit) ------------------------------------------------- #
@adapter("go-pot", lambda o: "phase" in o and "id" in o, dirs=("gopot",))
def p_gopot(o, ctx):
    req = http_request(o)
    if req and o.get("qs"):
        req += "?" + str(o["qs"])
    return event("go-pot", o, "http-tarpit", session=o.get("id"), label=str(o.get("phase") or "event"),
                 request=req if o.get("phase") in (None, "start") else None,
                 duration=o.get("duration") if isinstance(o.get("duration"), (int, float)) else None)


# ---- H0neytr4p (HTTP/S traps) --------------------------------------------- #
@adapter("h0neytr4p", lambda o: "trapped" in o or "trapped_for" in o)
def p_h0neytr4p(o, ctx):
    trapped = str(o.get("trapped", "")).lower() in ("true", "1", "yes")
    label = ("trap: %s" % o.get("trapped_for")) if trapped and o.get("trapped_for") else "request"
    return event("h0neytr4p", o, str(o.get("protocol") or "http").lower(), new_session=True,
                 label=short(label, 60), request=http_request(o),
                 text=str(first(o, *PATH_KEYS) or "") or None, tags=["exploit-attempt"] if trapped else [])


# ---- Hellpot (HTTP tarpit) ------------------------------------------------ #
@adapter("hellpot", lambda o: "REMOTE_ADDR" in o or "USERAGENT" in o)
def p_hellpot(o, ctx):
    if not o.get("REMOTE_ADDR"):
        return None
    return event("hellpot", o, "http-tarpit", 80, new_session=True,
                 label=short(o.get("message") or "request", 40),
                 request="GET %s" % o.get("URL") if o.get("URL") else None,
                 duration=o.get("DURATION") if isinstance(o.get("DURATION"), (int, float)) else None)


# ---- Heralding (credential catcher, CSV + session JSON) ------------------- #
HERALDING_ROW = re.compile(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(\.\d+)?,")


@adapter("heralding-csv", lambda line: line.startswith("timestamp,auth_id") or bool(HERALDING_ROW.match(line)),
         fmt="csv", hp="heralding")
def p_heralding_csv(line, ctx):
    if line.startswith("timestamp,"):
        return None
    row = next(csv.reader([line]))
    if len(row) < 10:
        return None
    ts, _auth, sid, src, _sport, dip, dport, proto, user, pw = row[:10]
    return event("heralding", {"timestamp": ts, "src_ip": src, "dst_ip": dip, "dst_port": dport},
                 proto or "auth", session=sid, label=(proto or "auth") + " login",
                 user=user, password=pw, ok=False)


@adapter("heralding", lambda o: "auth_attempts" in o or "num_auth_attempts" in o)
def p_heralding(o, ctx):
    proto = str(o.get("protocol") or "auth")
    base = event("heralding", o, proto, session=o.get("session_id"), label=proto + " session")
    if isinstance(o.get("duration"), (int, float)):
        base["duration"] = o["duration"]
    out = [base]
    common = {k: base[k] for k in ("hp", "ts", "src", "dst_port", "service")}
    for a in aslist(o.get("auth_attempts")):
        if isinstance(a, dict):
            out.append(dict(common, label=proto + " login", ok=False,
                            user=str(a.get("username", "")), password=str(a.get("password", ""))))
    if not o.get("auth_attempts") and (o.get("username") or o.get("password")):  # ES export
        out.append(dict(common, label=proto + " login", ok=False,
                        user=str(o.get("username", "")), password=str(o.get("password", ""))))
    return out


# ---- Honeyaml (fake REST API) --------------------------------------------- #
@adapter("honeyaml", lambda o: "path_type" in o or ("status_code" in o and "path" in o and "src_ip" in o))
def p_honeyaml(o, ctx):
    ev = event("honeyaml", o, "http-api", new_session=True, label=short(o.get("action") or "request", 40),
               request=http_request(o), text=str(o.get("body") or "") or None)
    if o.get("username"):
        ev.update(user=str(o["username"]), password=str(o.get("password", "")), ok=False)
    return ev


# ---- qeeqbox honeypots (30 low-interaction services) ---------------------- #
@adapter("honeypots", lambda o: "action" in o and str(o.get("server", "")).endswith("_server"))
def p_honeypots(o, ctx):
    svc = str(o.get("server", "unknown")).replace("_server", "")
    action = str(o.get("action", ""))
    ev = event("honeypots", o, svc, label="%s %s" % (svc, action))
    if action == "connection":
        ev["new_session"] = True
    elif action == "login" or o.get("username"):
        ev.update(user=str(o.get("username", "")), password=str(o.get("password", "")),
                  ok=str(o.get("status", "")).lower() in ("success", "true"))
    else:
        data = o.get("data")
        txt = data if isinstance(data, str) else json.dumps(data, default=str) if data else ""
        ev["request"] = "%s %s" % (action, short(txt, 120)) if txt else action
        ev["text"] = txt or None
    return ev


# ---- Honeytrap (catch-all, raw payloads) ---------------------------------- #
@adapter("honeytrap", lambda o: isinstance(o.get("attack_connection"), dict))
def p_honeytrap(o, ctx):
    c = o.get("attack_connection") or {}
    payload = printable(from_hex(dig(c, "payload.data_hex", ""))) if dig(c, "payload.data_hex") else ""
    port = to_port(c.get("local_port")) or to_port(o.get("dest_port"))
    proto = str(c.get("protocol") or "tcp").lower()
    return event("honeytrap", {"timestamp": o.get("timestamp") or o.get("@timestamp"),
                               "src_ip": c.get("remote_ip") or o.get("src_ip"),
                               "dst_ip": c.get("local_ip") or o.get("dest_ip"), "dst_port": port},
                 "%s/%s" % (proto, port) if port else proto, new_session=True, label="connection",
                 request=first_line(payload) or None, text=payload or None)


# ---- IPPHoney (internet printing protocol) -------------------------------- #
@adapter("ipphoney", lambda o: _eid(o, "ipphoney."))
def p_ipphoney(o, ctx):
    eid = str(o.get("eventid", ""))
    req = "%s %s" % (o.get("request", "") or o.get("request_method", ""), o.get("url", "") or "")
    return event("ipphoney", o, "ipp", 631, new_session=eid.endswith("connect"),
                 label=short(o.get("operation") or eid.split(".", 1)[-1], 40), request=req.strip() or None)


# ---- Log4Pot (Log4Shell) -------------------------------------------------- #
@adapter("log4pot", lambda o: o.get("reason") in ("request", "exploit", "start") and
         ("client" in o or "server_port" in o or "deobfuscated_payload" in o))
def p_log4pot(o, ctx):
    reason = o.get("reason")
    if reason == "start":
        return None
    headers = o.get("headers") if isinstance(o.get("headers"), dict) else {}
    ua = next((v for k, v in headers.items() if str(k).lower() == "user-agent"), None)
    ev = event("log4pot", o, "http", 8080, new_session=reason == "request", label=str(reason),
               request=short(o.get("request") or o.get("request_uri") or "", 140) or None, ua=ua)
    if reason == "exploit":
        ev["tags"] = ["exploit-attempt"]
        ev["label"] = "log4shell exploit"
        ev["text"] = "%s %s" % (o.get("payload", ""), o.get("deobfuscated_payload", ""))
        ev["text_tag"] = "exploit-callback"
    return ev


# ---- Mailoney (SMTP) ------------------------------------------------------ #
SMTP_RE = re.compile(r"^\s*(EHLO|HELO|MAIL|RCPT|DATA|QUIT|AUTH|RSET|NOOP|STARTTLS|VRFY|EXPN)\b", re.I)


@adapter("mailoney", lambda o: isinstance(o.get("data"), str) and bool(SMTP_RE.match(o["data"])) or "emails" in o)
def p_mailoney(o, ctx):
    data = str(o.get("data") or "")
    verb = SMTP_RE.match(data)
    return event("mailoney", o, "smtp", 25, session="%s:%s" % (o.get("src_ip"), o.get("src_port")),
                 label="smtp " + (verb.group(1).upper() if verb else "data"),
                 request=short(data, 120) if data else None, text=data or None)


# ---- MedPot (HL7 / FHIR) -------------------------------------------------- #
def hl7_summary(text):
    if text.startswith("MSH"):
        fields = text.split("\r", 1)[0].split("\n", 1)[0].split("|")
        mtype = fields[8] if len(fields) > 8 else ""
        sender = fields[2] if len(fields) > 2 else ""
        return short("HL7 %s from %s" % (mtype or "?", sender or "?"), 140)
    return first_line(text)


# Upstream MedPot logs {"level","message","time":"2018.09.09 17:20:49","port","ip","data"}, where
# "port" is the attacker's source port; T-Pot's build logs src_ip / dest_port instead.
@adapter("medpot", lambda o: "data" in o and "level" in o and "message" in o and ("src_ip" in o or "ip" in o))
def p_medpot(o, ctx):
    if not o.get("src_ip") and o.get("ip"):
        o = dict(o, src_ip=o["ip"])
    text = printable(from_b64(o.get("data", ""))) if o.get("data") else ""
    return event("medpot", o, "hl7", 2575, new_session="connection" in str(o.get("message", "")).lower(),
                 label=short(o.get("message") or "event", 40), request=hl7_summary(text) or None,
                 text=text or None, tags=["medical-scan"])


# ---- Miniprint (network printer / PJL) ------------------------------------ #
@adapter("miniprint", lambda o: "job_text" in o or ("event" in o and "action" in o and "src_ip" in o))
def p_miniprint(o, ctx):
    info, evname = str(o.get("info", "")), str(o.get("event", ""))
    job = str(o.get("job_text") or "")
    return event("miniprint", o, "pjl", 9100,
                 new_session=info == "Connection opened" or evname in ("connection_opened", "new_connection"),
                 label=short(evname or info or "event", 40),
                 request=("print job: " + short(job, 110)) if job else (short(o.get("command"), 120) or None),
                 text=job or None)


# ---- RDP honeypot --------------------------------------------------------- #
@adapter("rdphoneypot", lambda o: _eid(o, "rdphoneypot."))
def p_rdphoneypot(o, ctx):
    eid = str(o.get("eventid", ""))
    ev = event("rdphoneypot", o, "rdp", 3389, session=o.get("session"),
               new_session=eid.endswith("connect"), label=eid.split(".", 1)[-1])
    if o.get("username"):
        ev.update(user=str(o["username"]), password=str(o.get("password", "")), ok=False)
    return ev


# ---- Redis honeypot ------------------------------------------------------- #
REDIS_READONLY = {"INFO", "PING", "COMMAND", "QUIT", "CLIENT", "SELECT", "DBSIZE", "KEYS", "GET",
                  "SCAN", "TYPE", "TTL", "EXISTS", "HELLO", "ECHO", "TIME", "ROLE"}
REDIS_META = {"time", "timestamp", "@timestamp", "level", "addr", "action", "src_ip", "src_port",
              "dest_ip", "dest_port", "type"}


@adapter("redishoneypot", lambda o: "action" in o and ("addr" in o or "msg" in o) and "server" not in o,
         dirs=("redis",))
def p_redis(o, ctx):
    action = str(o.get("action", ""))
    up = action.upper().split(" ")[0]
    ev = event("redishoneypot", o, "redis", 6379, label="redis " + (action.lower() or "event"))
    if up in ("NEWCONNECT", "CONNECT"):
        ev["new_session"] = True
        return ev
    args = " ".join(str(v) for k, v in o.items() if k not in REDIS_META and v not in (None, ""))
    line = ("%s %s" % (action, args)).strip()
    if up == "AUTH":
        ev.update(user="default", password=args, ok=False)
    elif up in REDIS_READONLY:
        ev["request"] = short(line, 120)
    else:  # writes, CONFIG SET dir, SLAVEOF, MODULE LOAD, EVAL... are attacker actions
        ev["command"] = line
        if up in ("SLAVEOF", "REPLICAOF", "MODULE", "CONFIG", "EVAL", "SYSTEM.EXEC"):
            ev["tags"] = ["exploit-attempt"]
    return ev


# ---- SentryPeer (SIP / VoIP) ---------------------------------------------- #
@adapter("sentrypeer", lambda o: "sip_message" in o or "sip_user_agent" in o or "event_uuid" in o)
def p_sentrypeer(o, ctx):
    msg = str(o.get("sip_message") or "")
    method = o.get("sip_method") or (msg.split(" ", 1)[0] if msg else "")
    called = o.get("called_number") or ""
    return event("sentrypeer", o, "sip", 5060, new_session=True, label="sip " + str(method).lower(),
                 request=short("SIP %s %s" % (method, called), 140), ua=o.get("sip_user_agent"),
                 tags=["voip-scan"])


# ---- Tanner / Snare (web application) ------------------------------------- #
TANNER_BENIGN = {"index", "unknown", "", None}


@adapter("tanner", lambda o: isinstance(o.get("peer"), dict) and "path" in o, dirs=("snare",))
def p_tanner(o, ctx):
    det = dig(o, "response_msg.response.message.detection") or {}
    dname = det.get("name") if isinstance(det, dict) else None
    headers = o.get("headers") if isinstance(o.get("headers"), dict) else {}
    ua = next((v for k, v in headers.items() if str(k).lower() == "user-agent"), None)
    post = o.get("post_data")
    text = "%s %s" % (o.get("path", ""), json.dumps(post, default=str) if post else "")
    return event("tanner", o, "http", 80, session=o.get("uuid"), new_session=True,
                 label="web " + str(dname or "request"), request=http_request(o), ua=ua, text=text,
                 tags=["web-attack"] if dname not in TANNER_BENIGN else [])


# ---- Wordpot (WordPress) -------------------------------------------------- #
@adapter("wordpot", lambda o: "plugin" in o or ("url" in o and "src_ip" in o and "browser_family" in o))
def p_wordpot(o, ctx):
    ev = event("wordpot", o, "wordpress", 80, new_session=True,
               label="wordpress " + ("login" if o.get("username") else "request"),
               request=("GET %s" % o.get("url")) if o.get("url") else None)
    if o.get("username"):
        ev.update(user=str(o["username"]), password=str(o.get("password", "")), ok=False)
    return ev


# ---- Anything else with an attacker IP and a timestamp -------------------- #
def has_src_and_ts(o):
    return isinstance(o, dict) and bool(clean_ip(first(o, *SRC_KEYS))) and ts_any(o, *TS_KEYS) is not None


@adapter("generic", has_src_and_ts)
def p_generic(o, ctx):
    hp = ctx.get("hp") or "generic"
    ev = event(hp, o, str(first(o, "protocol", "service", "server") or hp).lower(), new_session=True,
               label=short(first(o, "eventid", "event_type", "action", "message", "msg") or "event", 50),
               request=http_request(o))
    if first(o, "username", "user") or o.get("password"):
        ev.update(user=str(first(o, "username", "user") or ""), password=str(o.get("password", "")), ok=False)
    cmd = first(o, "input", "command", "cmd")
    if isinstance(cmd, str):
        ev["command"] = cmd
    payload = first(o, "payload", "data", "body")
    if isinstance(payload, str):
        ev["text"] = payload
    return ev


# T-Pot's Elasticsearch / Logstash "type" field -> our kind
TPOT_TYPES = {
    "Adbhoney": "adbhoney", "Beelzebub": "beelzebub", "Ciscoasa": "ciscoasa",
    "CitrixHoneypot": "citrixhoneypot", "ConPot": "conpot-json", "Cowrie": "cowrie",
    "Ddospot": "ddospot", "Dicompot": "dicompot", "Dionaea": "dionaea", "ElasticPot": "elasticpot",
    "Endlessh": "endlessh", "Galah": "galah", "Glutton": "glutton", "Go-pot": "go-pot",
    "H0neytr4p": "h0neytr4p", "Hellpot": "hellpot", "Heralding": "heralding", "Honeyaml": "honeyaml",
    "Honeypots": "honeypots", "Honeytrap": "honeytrap", "Ipphoney": "ipphoney", "Log4pot": "log4pot",
    "Mailoney": "mailoney", "Medpot": "medpot", "Miniprint": "miniprint", "RDPHoneypot": "rdphoneypot",
    "Redishoneypot": "redishoneypot", "Sentrypeer": "sentrypeer", "Tanner": "tanner", "Wordpot": "wordpot",
}
TPOT_NOT_HONEYPOTS = {"Suricata", "P0f", "Fatt", "NGINX"}  # sensors/IDS, not attacker sessions


def is_tpot_es(o):
    src = o.get("_source") if isinstance(o.get("_source"), dict) else o
    return isinstance(src, dict) and (src.get("type") in TPOT_TYPES or src.get("type") in TPOT_NOT_HONEYPOTS) \
        and ("@timestamp" in src or "t-pot_hostname" in src or "src_ip" in src)


# Order matters only for ambiguous records; specific detectors first, generic last.
JSON_ORDER = [k for k, a in ADAPTERS.items() if a.fmt == "json" and k != "generic"] + ["generic"]
TEXT_ORDER = [k for k, a in ADAPTERS.items() if a.fmt in ("text", "csv")]
HINTS = {}
for _a in ADAPTERS.values():
    for _d in _a.dirs:
        HINTS.setdefault(_d.lower(), _a.name)
HINTS.update({"cowrie": "cowrie", "conpot": "conpot-json"})
KIND_HP = {a.name: a.hp for a in ADAPTERS.values()}
KIND_HP.update({"cowrie": "cowrie", "conpot-json": "conpot", "conpot-text": "conpot",
                "tpot-es": "t-pot export"})
# T-Pot folders that hold sensors / infrastructure, not honeypot sessions
TPOT_SKIP_DIRS = {"nginx", "suricata", "p0f", "fatt", "elk", "elasticsearch", "kibana", "logstash",
                  "ewsposter", "spiderfoot", "tpotinit", "map", "attack-map", "ews"}


# --------------------------------------------------------------------------- #
# MITRE ATT&CK mapping
# --------------------------------------------------------------------------- #
# technique id -> (name, tactic). Tactics use ATT&CK's kill-chain phase names. T0xxx are
# ATT&CK for ICS techniques (kill chain "mitre-ics-attack").

ATTACK = {
    "T1595":     ("Active Scanning", "reconnaissance"),
    "T1595.001": ("Active Scanning: Scanning IP Blocks", "reconnaissance"),
    "T1595.002": ("Active Scanning: Vulnerability Scanning", "reconnaissance"),
    "T1190":     ("Exploit Public-Facing Application", "initial-access"),
    "T1078":     ("Valid Accounts", "initial-access"),
    "T1059.004": ("Command and Scripting Interpreter: Unix Shell", "execution"),
    "T1053.003": ("Scheduled Task/Job: Cron", "persistence"),
    "T1098":     ("Account Manipulation", "persistence"),
    "T1098.004": ("Account Manipulation: SSH Authorized Keys", "persistence"),
    "T1136.001": ("Create Account: Local Account", "persistence"),
    "T1543.002": ("Create or Modify System Process: Systemd Service", "persistence"),
    "T1546.004": ("Event Triggered Execution: Unix Shell Configuration Modification", "persistence"),
    "T1037.004": ("Boot or Logon Initialization Scripts: RC Scripts", "persistence"),
    "T1548.001": ("Abuse Elevation Control Mechanism: Setuid and Setgid", "privilege-escalation"),
    "T1548.003": ("Abuse Elevation Control Mechanism: Sudo and Sudo Caching", "privilege-escalation"),
    "T1070.002": ("Indicator Removal: Clear Linux or Mac System Logs", "defense-evasion"),
    "T1070.003": ("Indicator Removal: Clear Command History", "defense-evasion"),
    "T1222.002": ("File and Directory Permissions Modification: Linux and Mac", "defense-evasion"),
    "T1562.001": ("Impair Defenses: Disable or Modify Tools", "defense-evasion"),
    "T1562.004": ("Impair Defenses: Disable or Modify System Firewall", "defense-evasion"),
    "T1110.001": ("Brute Force: Password Guessing", "credential-access"),
    "T1003.008": ("OS Credential Dumping: /etc/passwd and /etc/shadow", "credential-access"),
    "T1082":     ("System Information Discovery", "discovery"),
    "T1033":     ("System Owner/User Discovery", "discovery"),
    "T1057":     ("Process Discovery", "discovery"),
    "T1016":     ("System Network Configuration Discovery", "discovery"),
    "T1049":     ("System Network Connections Discovery", "discovery"),
    "T1083":     ("File and Directory Discovery", "discovery"),
    "T1087.001": ("Account Discovery: Local Account", "discovery"),
    "T1046":     ("Network Service Discovery", "discovery"),
    "T1105":     ("Ingress Tool Transfer", "command-and-control"),
    "T1090":     ("Proxy", "command-and-control"),
    "T1496":     ("Resource Hijacking", "impact"),
    "T1489":     ("Service Stop", "impact"),
    "T0846":     ("Remote System Discovery (ICS)", "discovery"),
}
TACTIC_ORDER = ["reconnaissance", "initial-access", "execution", "persistence", "privilege-escalation",
                "defense-evasion", "credential-access", "discovery", "command-and-control", "impact"]

# Shell commands (Cowrie, ADBHoney, Beelzebub, Redis writes...) -> techniques
ATTACK_CMD = [
    ("T1082", r"\buname\b|/proc/(cpuinfo|meminfo|version)|\blscpu\b|\bnproc\b|\bfree\s+-|/etc/(issue|os-release|lsb-release)|"
              r"\bdmidecode\b|\blsblk\b|\bdf\s+-|\bhostnamectl\b"),
    ("T1033", r"\bwhoami\b|(^|[;&|\s])id(?=[\s;&|]|$)|(^|[;&|\s])w(?=[\s;&|]|$)|\bwho\b|\blast\b"),
    ("T1057", r"\bps\s+(aux|-ef|-A)|(^|[;&|\s])ps(?=[\s;&|]|$)|\btop\b|\bpgrep\b"),
    ("T1016", r"\bifconfig\b|\bip\s+(a|addr|route|link)\b|/etc/resolv\.conf|\broute\s+-n|\bhostname\s+-I"),
    ("T1049", r"\bnetstat\b|\bss\s+-[a-z]*[tun]"),
    ("T1083", r"(^|[;&|\s])ls(?=[\s;&|]|$)|\bfind\s+/|\blocate\b"),
    ("T1087.001", r"/etc/passwd|\bgetent\s+passwd"),
    ("T1003.008", r"/etc/shadow"),
    ("T1046", r"\bnmap\b|\bmasscan\b|\bzmap\b"),
    ("T1105", r"\bwget\b|\bcurl\b|\btftp\b|\bftpget\b|(^|[;&|\s])scp\s|\blwp-download\b|/dev/tcp/"),
    ("T1053.003", r"\bcrontab\b|/etc/cron|/var/spool/cron"),
    ("T1098.004", r"authorized_keys"),
    ("T1136.001", r"\buseradd\b|\badduser\b"),
    ("T1098", r"\bchpasswd\b|(^|[;&|\s])passwd\b|\busermod\b"),
    ("T1543.002", r"systemctl\s+(enable|daemon-reload)|/etc/systemd/system|/lib/systemd/system"),
    ("T1546.004", r"\.bashrc|\.bash_profile|\.profile\b|/etc/profile"),
    ("T1037.004", r"/etc/rc\.local|/etc/init\.d"),
    ("T1548.001", r"chmod\s+(u\+s|[0-7]?[4-7][0-7]{3}\b)"),
    ("T1548.003", r"\bsudo\b"),
    ("T1222.002", r"chmod\s+(-R\s+)?([ugoa]*\+x|0?7[0-7]{2}\b)|\bchattr\b"),
    ("T1070.003", r"history\s+-c|unset\s+HISTFILE|HISTFILE=/dev/null|export\s+HISTFILE=|HISTSIZE=0"),
    ("T1070.002", r"rm\s+-r?f+\s+/var/log|>\s*/var/log/\S+|\bshred\b"),
    ("T1562.004", r"iptables\s+-F|ufw\s+disable|systemctl\s+(stop|disable)\s+firewalld"),
    ("T1562.001", r"setenforce\s+0|systemctl\s+(stop|disable)\s+(apparmor|auditd|aliyun)|aegis|qcloud|uninstall\.sh"),
    ("T1496", r"xmrig|stratum\+tcp|minerd|cpuminer|c3pool|nanopool|moneroocean|--donate-level|nicehash|supportxmr"),
    ("T1489", r"\bpkill\b|\bkillall\b|kill\s+-9"),
]
ATTACK_CMD = [(t, re.compile(rx, re.I)) for t, rx in ATTACK_CMD]

# IP tags -> techniques
TAG_ATTACK = {
    "scanner": "T1595.001", "voip-scan": "T1595.001", "medical-scan": "T1595", "ics-scan": "T0846",
    "exploit-attempt": "T1190", "web-attack": "T1190", "tunnel-abuse": "T1090",
}


def attack_url(tid):
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"


# --------------------------------------------------------------------------- #
# GeoIP (offline: MaxMind-format .mmdb or DB-IP / IP2Location CSV)
# --------------------------------------------------------------------------- #

class MMDB:
    """Minimal pure-Python reader for MaxMind DB files (GeoLite2, DB-IP Lite, IPinfo Lite...)."""

    MARKER = b"\xab\xcd\xefMaxMind.com"

    def __init__(self, path):
        import mmap
        self.fh = open(path, "rb")
        self.buf = mmap.mmap(self.fh.fileno(), 0, access=mmap.ACCESS_READ)
        start = self.buf.rfind(self.MARKER, max(0, len(self.buf) - 128 * 1024))
        if start < 0:
            raise ValueError("not a MaxMind DB file")
        self.meta, _ = self._decode(start + len(self.MARKER), start + len(self.MARKER))
        self.nodes = self.meta["node_count"]
        self.rec = self.meta["record_size"]
        if self.rec not in (24, 28, 32):
            raise ValueError("unsupported record size %s" % self.rec)
        self.node_bytes = self.rec * 2 // 8
        self.tree = self.nodes * self.node_bytes
        self.data = self.tree + 16
        self.v6 = self.meta.get("ip_version") == 6
        self.v4_start = 0
        if self.v6:  # IPv4 lives under ::/96
            node = 0
            for _ in range(96):
                if node >= self.nodes:
                    break
                node = self._read(node, 0)
            self.v4_start = node
        self.type = str(self.meta.get("database_type", "mmdb"))

    def _read(self, node, bit):
        b = self.buf
        off = node * self.node_bytes
        if self.rec == 24:
            o = off + bit * 3
            return int.from_bytes(b[o:o + 3], "big")
        if self.rec == 28:
            mid = b[off + 3]
            if bit == 0:
                return ((mid & 0xF0) << 20) | int.from_bytes(b[off:off + 3], "big")
            return ((mid & 0x0F) << 24) | int.from_bytes(b[off + 4:off + 7], "big")
        o = off + bit * 4
        return int.from_bytes(b[o:o + 4], "big")

    def _decode(self, off, base):
        """Decode one value at off; pointers are relative to base. Returns (value, next offset)."""
        b = self.buf
        ctrl = b[off]
        off += 1
        typ = ctrl >> 5
        if typ == 1:  # pointer
            ss, vvv = (ctrl >> 3) & 3, ctrl & 7
            if ss == 0:
                p = (vvv << 8) | b[off]
            elif ss == 1:
                p = ((vvv << 16) | int.from_bytes(b[off:off + 2], "big")) + 2048
            elif ss == 2:
                p = ((vvv << 24) | int.from_bytes(b[off:off + 3], "big")) + 526336
            else:
                p = int.from_bytes(b[off:off + 4], "big")
            val, _ = self._decode(base + p, base)
            return val, off + ss + 1
        if typ == 0:
            typ = 7 + b[off]
            off += 1
        size = ctrl & 0x1F
        if size == 29:
            size = 29 + b[off]
            off += 1
        elif size == 30:
            size = 285 + int.from_bytes(b[off:off + 2], "big")
            off += 2
        elif size == 31:
            size = 65821 + int.from_bytes(b[off:off + 3], "big")
            off += 3
        if typ == 2:
            return b[off:off + size].decode("utf-8", "replace"), off + size
        if typ == 7:
            out = {}
            for _ in range(size):
                k, off = self._decode(off, base)
                v, off = self._decode(off, base)
                out[k] = v
            return out, off
        if typ == 11:
            out = []
            for _ in range(size):
                v, off = self._decode(off, base)
                out.append(v)
            return out, off
        if typ in (5, 6, 9, 10):
            return int.from_bytes(b[off:off + size], "big"), off + size
        if typ == 8:
            return int.from_bytes(b[off:off + size], "big", signed=True), off + size
        if typ == 3:
            import struct
            return struct.unpack(">d", b[off:off + 8])[0], off + 8
        if typ == 15:
            import struct
            return struct.unpack(">f", b[off:off + 4])[0], off + 4
        if typ == 14:
            return bool(size), off
        if typ == 4:
            return bytes(b[off:off + size]), off + size
        return None, off + size

    def get(self, ip):
        addr = ipaddress.ip_address(ip)
        if addr.version == 4:
            if not self.v6:
                node, bits = 0, 32
            else:
                node, bits = self.v4_start, 32
        else:
            if not self.v6:
                return None
            node, bits = 0, 128
        n = int(addr)
        for i in range(bits - 1, -1, -1):
            if node >= self.nodes:
                break
            node = self._read(node, (n >> i) & 1)
        if node <= self.nodes:
            return None  # == nodes: not found
        val, _ = self._decode(self.data + (node - self.nodes - 16), self.data)
        return val


class CSVGeo:
    """DB-IP Lite / IP2Location LITE style CSV ranges (start,end,...). Also .csv.gz."""

    def __init__(self, path):
        import bisect
        self.bisect = bisect
        rows = {4: [], 6: []}
        opener = gzip.open if str(path).lower().endswith(".gz") else open
        with opener(path, "rt", encoding="utf-8", errors="replace", newline="") as fh:
            for row in csv.reader(fh):
                if len(row) < 3:
                    continue
                try:
                    a, b = self._ip(row[0]), self._ip(row[1])
                except ValueError:
                    continue  # header
                rest = [x.strip() for x in row[2:]]
                rec = {}
                if rest and re.fullmatch(r"\d+", rest[0]):  # dbip-asn: start,end,asn,org
                    rec = {"asn": int(rest[0]), "as_org": rest[1] if len(rest) > 1 else ""}
                else:
                    cc = next((x for x in rest if re.fullmatch(r"[A-Z]{2}", x) and x != "ZZ"), "")
                    rec = {"cc": cc}
                    if len(rest) >= 6 and rest[0] in ("AF", "AN", "AS", "EU", "NA", "OC", "SA") and rest[1] == cc:
                        rec["city"] = rest[3]  # dbip-city: continent,country,region,city,lat,lon
                ver = 6 if a[0] == 6 else 4
                rows[ver].append((a[1], b[1], rec))
        self.idx = {}
        for ver, r in rows.items():
            r.sort(key=lambda x: x[0])
            self.idx[ver] = ([x[0] for x in r], r)
        self.type = "csv"

    @staticmethod
    def _ip(s):
        s = s.strip().strip('"')
        if s.isdigit():  # IP2Location stores integers
            n = int(s)
            return (4 if n < 2 ** 32 else 6), n
        a = ipaddress.ip_address(s)
        return a.version, int(a)

    def get(self, ip):
        a = ipaddress.ip_address(ip)
        starts, rows = self.idx.get(a.version, ([], []))
        i = self.bisect.bisect_right(starts, int(a)) - 1
        if i >= 0 and rows[i][0] <= int(a) <= rows[i][1]:
            return rows[i][2]
        return None


def normalise_geo(rec):
    """Any supported DB record -> {"cc", "country", "city", "asn", "as_org"} (missing keys omitted)."""
    if not isinstance(rec, dict):
        return {}
    out = {}
    cc = dig(rec, "country.iso_code") or dig(rec, "registered_country.iso_code") or rec.get("country_code") \
        or rec.get("cc")
    if isinstance(cc, str) and len(cc) == 2:
        out["cc"] = cc.upper()
    name = dig(rec, "country.names.en") or (rec.get("country") if isinstance(rec.get("country"), str) else None)
    if name:
        out["country"] = name
    city = dig(rec, "city.names.en") or rec.get("city")
    if isinstance(city, str) and city:
        out["city"] = city
    asn = rec.get("autonomous_system_number") or rec.get("asn")
    if isinstance(asn, str):
        asn = asn.upper().lstrip("AS")
        asn = int(asn) if asn.isdigit() else None
    if isinstance(asn, int):
        out["asn"] = asn
    org = rec.get("autonomous_system_organization") or rec.get("as_name") or rec.get("as_org")
    if org:
        out["as_org"] = str(org)
    return out


class GeoDB:
    """One or more databases; later ones fill in fields the earlier ones lack (e.g. City + ASN)."""

    def __init__(self, paths):
        self.dbs, self.names = [], []
        for p in paths:
            p = Path(p)
            db = MMDB(p) if p.suffix.lower() == ".mmdb" else CSVGeo(p)
            self.dbs.append(db)
            self.names.append("%s (%s)" % (p.name, db.type))
        self.cache = {}

    def lookup(self, ip):
        if ip in self.cache:
            return self.cache[ip]
        out = {}
        for db in self.dbs:
            try:
                rec = normalise_geo(db.get(ip))
            except (ValueError, IndexError, KeyError, TypeError):
                rec = {}
            for k, v in rec.items():
                out.setdefault(k, v)
        self.cache[ip] = out
        return out


def find_geo_dbs(root):
    """GeoIP files dropped in ~/.honeycomb/ or the log root are picked up automatically."""
    found = []
    for d in (Path.home() / ".honeycomb", root):
        if d.is_dir():
            for f in sorted(d.iterdir()):
                n = f.name.lower()
                if f.is_file() and (n.endswith(".mmdb") or (("ip" in n or "geo" in n or "asn" in n or "country" in n)
                                                           and re.search(r"\.csv(\.gz)?$", n))):
                    found.append(f)
    return found


# --------------------------------------------------------------------------- #
# Aggregation
# --------------------------------------------------------------------------- #

class Agg:
    """Statistics for one view (a single sensor, or all sensors combined)."""

    def __init__(self):
        self.events = 0
        self.first = None
        self.last = None
        self.ips = Counter()
        self.sessions = 0
        self.session_ids = set()
        self.login_fail = 0
        self.login_ok = 0
        self.users = Counter()
        self.passwords = Counter()
        self.combos = Counter()
        self.ok_combos = Counter()
        self.commands = Counter()
        self.cmd_cats = Counter()
        self.urls = Counter()
        self.hashes = Counter()
        self.ports = Counter()
        self.protocols = Counter()
        self.clients = Counter()
        self.hassh = Counter()
        self.sshkeys = Counter()
        self.tunnels = Counter()
        self.requests = Counter()
        self.eventtypes = Counter()
        self.honeypots = Counter()
        self.hourly = Counter()
        self.dur_sum = 0.0
        self.dur_n = 0

    def base(self, ts, ip, etype):
        self.events += 1
        self.eventtypes[etype] += 1
        if ip:
            self.ips[ip] += 1
        if ts:
            if self.first is None or ts < self.first:
                self.first = ts
            if self.last is None or ts > self.last:
                self.last = ts
            self.hourly[ts.strftime("%Y-%m-%dT%H")] += 1

    def stats(self, top=TOP_N):
        def t(c, n=top):
            return [[str(k), v] for k, v in c.most_common(n)]
        return {
            "kpi": {
                "events": self.events,
                "unique_ips": len(self.ips),
                "sessions": self.sessions,
                "login_attempts": self.login_fail + self.login_ok,
                "login_success": self.login_ok,
                "commands": sum(self.commands.values()),
                "unique_commands": len(self.commands),
                "unique_hashes": len(self.hashes),
                "unique_urls": len(self.urls),
                "protocols": len(self.protocols),
                "honeypots": len(self.honeypots),
                "requests": sum(self.requests.values()),
                "avg_session_s": round(self.dur_sum / self.dur_n, 1) if self.dur_n else None,
            },
            "first": iso(self.first),
            "last": iso(self.last),
            "hourly": sorted([k, v] for k, v in self.hourly.items()),
            "top_ips": t(self.ips),
            "usernames": t(self.users),
            "passwords": t(self.passwords),
            "combos": t(self.combos),
            "ok_combos": t(self.ok_combos),
            "commands": t(self.commands, 25),
            "cmd_cats": t(self.cmd_cats, 20),
            "urls": t(self.urls),
            "hashes": t(self.hashes),
            "ports": t(self.ports),
            "protocols": t(self.protocols),
            "clients": t(self.clients),
            "hassh": t(self.hassh),
            "sshkeys": t(self.sshkeys),
            "tunnels": t(self.tunnels),
            "requests": t(self.requests, 20),
            "eventtypes": t(self.eventtypes, 25),
            "honeypots": t(self.honeypots, 40),
        }


class Registry:
    """Master IOC registry across all sensors."""

    def __init__(self):
        self.ips = {}
        self.other = {}  # (type, value) -> record

    def ip(self, ip, ts, sensor, event=True):
        """event=False records a reference (e.g. payload host in a URL), not traffic from it."""
        r = self.ips.get(ip)
        if r is None:
            r = self.ips[ip] = {"first": ts, "last": ts, "sensors": set(), "events": 0, "refs": 0,
                                "fail": 0, "ok": 0, "cmds": 0, "dl": 0, "dl_fail": 0,
                                "tags": set(), "protos": set(), "att": {}}
        if event:
            r["events"] += 1
        else:
            r["refs"] += 1
        r["sensors"].add(sensor)
        if ts:
            if r["first"] is None or ts < r["first"]:
                r["first"] = ts
            if r["last"] is None or ts > r["last"]:
                r["last"] = ts
        return r

    def add(self, typ, value, ts, sensor, tags, src_ip=None):
        key = (typ, value)
        r = self.other.get(key)
        if r is None:
            r = self.other[key] = {"first": ts, "last": ts, "sensors": set(), "count": 0,
                                   "tags": set(), "ips": set()}
        r["count"] += 1
        r["sensors"].add(sensor)
        if isinstance(tags, str):
            tags = (tags,)
        r["tags"].update(t for t in tags if t)
        if src_ip:
            r["ips"].add(src_ip)
        if ts:
            if r["first"] is None or ts < r["first"]:
                r["first"] = ts
            if r["last"] is None or ts > r["last"]:
                r["last"] = ts


# --------------------------------------------------------------------------- #
# Event handlers
# --------------------------------------------------------------------------- #

class Analyzer:
    def __init__(self, ipf, since, until, bruteforce_threshold, dedupe="line"):
        self.ipf = ipf
        self.since = since
        self.until = until
        self.bf = bruteforce_threshold
        self.dedupe = dedupe
        self.dupe_files = 0
        self.total = Agg()
        self.per = {}
        self.series = defaultdict(Counter)  # sensor -> hourly counter (overview stack)
        self.reg = Registry()
        self.self_ips = set()
        self.excluded = 0
        self.out_of_range = 0
        self.bad_lines = 0
        self.dupes = 0
        self.creds = Counter()  # (sensor, user, pass, ok) -> n
        self.files = []
        self.no_source = 0          # records without an attacker IP (startup lines etc.)
        self.es_geo = {}            # geo that T-Pot's Logstash already attached to exported records
        self.skipped_types = Counter()  # T-Pot export records from IDS/sensors, not honeypots

    def _aggs(self, sensor):
        if sensor not in self.per:
            self.per[sensor] = Agg()
        return (self.per[sensor], self.total)

    def _window(self, ts):
        if ts is None:
            # No timestamp: fine for a full run, but it can't be shown to be inside a date range
            return not (self.since or self.until)
        if self.since and ts < self.since:
            return False
        if self.until and ts >= self.until:
            return False
        return True

    def _urls(self, text, ts, sensor, ip, tag, aggs):
        if tag in DECODE_TAGS and ("%" in text or "+" in text):
            # Network requests are usually URL-encoded: "GET /x?cmd=wget+http://1.2.3.4/Mozi.m+-O+/tmp/a"
            # must yield http://1.2.3.4/Mozi.m, not a URL with "+-O+/tmp/a" glued on.
            text = unquote_plus(text)
        for m in URL_RE.finditer(text):
            url = m.group(1).rstrip(".,")
            self._url(url, ts, sensor, ip, tag, aggs)

    def _url(self, url, ts, sensor, ip, tag, aggs):
        if not URL_SCHEME_RE.match(url):
            return  # Cowrie puts local paths (/home/pi/x) in "url" for uploads - not a URL
        for a in aggs:
            a.urls[url] += 1
        try:
            host = (urlsplit(url).hostname or "").lower()
        except ValueError:
            host = ""
        is_ip = bool(host) and valid_ip(host)
        url_tags = [tag]
        if is_ip and tag in ("seen-in-command", "seen-in-payload", "exploit-callback", "exploit-payload",
                             "download-url"):
            url_tags.append("raw-ip-host")  # wget http://1.2.3.4/x.sh is staging, not a lookup
        self.reg.add("url", url, ts, sensor, url_tags, ip)
        if not host:
            return
        if is_ip:
            if not self.ipf.blocked(host):
                r = self.reg.ip(host, ts, sensor, event=False)
                r["tags"].add("payload-host")
        elif "." in host:
            # Only a domain something was actually fetched from is a payload host. A domain
            # merely mentioned in a command (curl ipinfo.io) is just "referenced".
            dtag = "payload-host" if tag in FETCH_TAGS else "referenced-host"
            self.reg.add("domain", host, ts, sensor, dtag, ip)

    @staticmethod
    def _att(r, sensor, *tids):
        if r is not None:
            r["att"].setdefault(sensor, set()).update(t for t in tids if t)

    def _login(self, aggs, r, sensor, user, pw, ok):
        self._att(r, sensor, "T1078" if ok else "T1110.001")
        user, pw = str(user or ""), str(pw or "")
        combo = "%s / %s" % (user, pw)
        for a in aggs:
            if ok:
                a.login_ok += 1
                a.ok_combos[combo] += 1
            else:
                a.login_fail += 1
            a.users[user] += 1
            a.passwords[pw] += 1
            a.combos[combo] += 1
        self.creds[(sensor, user, pw, bool(ok))] += 1
        if r is not None:
            r["ok" if ok else "fail"] += 1

    def _command(self, aggs, r, sensor, ip, ts, cmd):
        self._att(r, sensor, "T1059.004", *[t for t, rx in ATTACK_CMD if rx.search(cmd)])
        cats = [name for name, rx in CMD_CATEGORIES if rx.search(cmd)]
        for a in aggs:
            a.commands[short(cmd, 200)] += 1
            for c in cats:
                a.cmd_cats[c] += 1
        if r is not None:
            r["cmds"] += 1
            for c in cats:
                if c in ("privilege escalation", "persistence", "cryptomining", "defense evasion"):
                    r["tags"].add(c.replace(" ", "-"))
        for m in URL_RE.finditer(cmd):
            # which command segment is the URL in? "cd /tmp; wget http://x/a -O a || curl -O http://x/a"
            seg = CMD_SEP_RE.split(cmd[:m.start()])[-1]
            tag = "download-url" if DL_VERB_RE.search(seg) else "seen-in-command"
            self._url(m.group(1).rstrip(".,"), ts, sensor, ip, tag, aggs)

    # ---- Every other honeypot (normalised events from the adapters) -------- #
    def generic(self, ev, sensor):
        if not isinstance(ev, dict):
            return
        if ev.get("dst_ip"):
            self.self_ips.add(ev["dst_ip"])  # learn our own IPs even outside the window
        ts = ev.get("ts")
        if not self._window(ts):
            self.out_of_range += 1
            return
        ip = ev.get("src") or ""
        if not ip:
            self.no_source += 1
            return
        if self.ipf.blocked(ip):
            self.excluded += 1
            return
        hp = ev.get("hp") or "generic"
        svc = str(ev.get("service") or hp)
        aggs = self._aggs(sensor)
        label = "%s %s" % (hp, ev.get("label") or "event")
        for a in aggs:
            a.base(ts, ip, short(label, 60))
            a.honeypots[hp] += 1
        if ts:
            self.series[sensor][ts.strftime("%Y-%m-%dT%H")] += 1
        r = self.reg.ip(ip, ts, sensor)
        r["protos"].add(svc)
        r["tags"].update(ev.get("tags") or ())
        self._att(r, sensor, *[TAG_ATTACK.get(t) for t in ev.get("tags") or ()])

        new = False
        sid = ev.get("session")
        if sid not in (None, ""):
            key = (hp, str(sid))
            if key not in aggs[0].session_ids:
                aggs[0].session_ids.add(key)
                new = True
        elif ev.get("new_session"):
            new = True
        if new:
            for a in aggs:
                a.sessions += 1
                a.protocols[svc] += 1
                if ev.get("dst_port"):
                    a.ports[ev["dst_port"]] += 1

        if "user" in ev or "password" in ev:
            self._login(aggs, r, sensor, ev.get("user"), ev.get("password"), ev.get("ok"))
        if ev.get("command"):
            self._command(aggs, r, sensor, ip, ts, str(ev["command"]))
        if ev.get("request"):
            for a in aggs:
                a.requests["%s: %s" % (svc, short(ev["request"], 140))] += 1
        if ev.get("ua"):
            for a in aggs:
                a.clients[short(ev["ua"], 120)] += 1
        if isinstance(ev.get("duration"), (int, float)):
            for a in aggs:
                a.dur_sum += float(ev["duration"])
                a.dur_n += 1
        if ev.get("text"):
            text = str(ev["text"])[:20000]
            exploit = is_exploit(text)
            self._urls(text, ts, sensor, ip,
                       ev.get("text_tag") or ("exploit-payload" if exploit else "seen-in-payload"), aggs)
            if exploit:
                r["tags"].add("exploit-attempt")  # e.g. "GET /shell?cd /tmp;wget http://..." in a payload
                self._att(r, sensor, "T1190", "T1105")
        if ev.get("url"):
            self._url(str(ev["url"]), ts, sensor, ip, ev.get("url_tag") or "downloaded", aggs)
        sha = str(ev.get("sha256") or "").lower()
        if re.fullmatch(r"[0-9a-f]{64}", sha) and sha != EMPTY_SHA256:
            for a in aggs:
                a.hashes[sha] += 1
            self.reg.add("sha256", sha, ts, sensor, ev.get("hash_tag") or "captured", ip)
            r["dl"] += 1
            self._att(r, sensor, "T1105")

    def _es_geo(self, o):
        """T-Pot's Logstash adds GeoIP/ASN to every record - use it when no local DB is given."""
        ip = clean_ip(o.get("src_ip"))
        if not ip or ip in self.es_geo:
            return
        g = normalise_geo({
            "cc": first(o, "geoip.country_code2", "geoip.country_iso_code", "geoip.geo.country_iso_code"),
            "country": first(o, "geoip.country_name", "geoip.geo.country_name"),
            "city": first(o, "geoip.city_name", "geoip.geo.city_name"),
            "asn": first(o, "geoip.asn", "geoip.as.number", "geoip_ext.asn"),
            "as_org": first(o, "geoip.as_org", "geoip.as.organization.name", "geoip_ext.as_org")})
        if g:
            self.es_geo[ip] = g

    def dispatch(self, kind, o, sensor, ctx):
        """Route one parsed record to the right handler."""
        if kind == "tpot-es":
            o = o.get("_source") if isinstance(o.get("_source"), dict) else o
            self._es_geo(o)
            t = o.get("type")
            kind = TPOT_TYPES.get(t)
            if kind is None:
                self.skipped_types[str(t)] += 1
                return
            if kind in ("cowrie", "conpot-json"):  # Logstash renamed dst_* to dest_*
                o = dict(o)
                for a, b in (("dest_ip", "dst_ip"), ("dest_port", "dst_port")):
                    if a in o and b not in o:
                        o[b] = o[a]
            ad = ADAPTERS.get(kind)
            if ad is not None and ad.fmt not in ("json", "pyrepr"):  # Logstash already split it
                kind, ctx = "generic", dict(ctx, hp=ad.hp)
        if kind == "cowrie":
            self.cowrie(o, sensor)
        elif kind == "conpot-json":
            self.conpot_json(o, sensor)
        else:
            res = ADAPTERS[kind].parse(o, ctx)
            for ev in (res if isinstance(res, list) else [res]):
                self.generic(ev, sensor)

    # ---- Cowrie ----------------------------------------------------------- #
    def cowrie(self, e, sensor):
        eid = str(e.get("eventid", ""))
        ts = parse_ts(e.get("timestamp"))
        if eid == "cowrie.session.connect" and e.get("dst_ip"):
            self.self_ips.add(str(e["dst_ip"]))  # learn our own IPs even outside the window
        if not self._window(ts):
            self.out_of_range += 1
            return
        ip = str(e.get("src_ip") or "")
        if ip and self.ipf.blocked(ip):
            self.excluded += 1
            return
        aggs = self._aggs(sensor)
        short_eid = eid.replace("cowrie.", "", 1)
        for a in aggs:
            a.base(ts, ip, short_eid)
            a.honeypots["cowrie"] += 1
        if ts:
            self.series[sensor][ts.strftime("%Y-%m-%dT%H")] += 1
        r = self.reg.ip(ip, ts, sensor) if ip else None

        if eid == "cowrie.session.connect":
            port = e.get("dst_port")
            proto = e.get("protocol") or ("telnet" if port in (23, 2323) else "ssh")
            for a in aggs:
                a.sessions += 1
                if port is not None:
                    a.ports[port] += 1
                a.protocols[proto] += 1
            if r is not None:
                r["protos"].add(proto)
        elif eid in ("cowrie.login.failed", "cowrie.login.success"):
            self._login(aggs, r, sensor, e.get("username", ""), e.get("password", ""),
                        eid.endswith("success"))
        elif eid == "cowrie.command.input":
            self._command(aggs, r, sensor, ip, ts, str(e.get("input", "")))
        elif eid in ("cowrie.session.file_download", "cowrie.session.file_upload",
                     "cowrie.session.file_download.failed"):
            failed = eid.endswith(".failed")
            tag = "download-failed" if failed else ("downloaded" if "download" in eid else "uploaded")
            sha = str(e.get("shasum", "") or "").lower()
            url = e.get("url")
            if url:
                self._url(str(url), ts, sensor, ip, tag, aggs)
            if re.fullmatch(r"[0-9a-f]{64}", sha) and sha != EMPTY_SHA256:
                for a in aggs:
                    a.hashes[sha] += 1
                self.reg.add("sha256", sha, ts, sensor, tag, ip)
            if r is not None:
                r["dl_fail" if failed else "dl"] += 1
            self._att(r, sensor, "T1105")
        elif eid == "cowrie.client.version":
            v = short(e.get("version", ""), 120)
            for a in aggs:
                a.clients[v] += 1
        elif eid == "cowrie.client.fingerprint":
            # public key the attacker tried to log in with. A key reused across IPs ties them to
            # one operator; random keys from research scanners stay low (one source each).
            fp = ssh_key_fingerprint(e.get("key")) or str(e.get("fingerprint") or "")
            if fp:
                for a in aggs:
                    a.sshkeys[fp] += 1
                self.reg.add("ssh-key", fp, ts, sensor,
                             ["ssh-key-attempt", str(e.get("type") or "").lower() or None], ip)
        elif eid == "cowrie.telnet.exploit_attempt":
            cve = str(e.get("cve") or "").strip()
            label = "%s %s=%s" % (cve or "exploit", e.get("name", ""), e.get("value", ""))
            for a in aggs:
                a.requests["telnet: " + short(label, 140)] += 1
            if r is not None:
                r["tags"].add("exploit-attempt")
                if re.fullmatch(r"CVE-\d{4}-\d{4,}", cve, re.I):
                    r["tags"].add(cve.lower())
            self._att(r, sensor, "T1190")
        elif eid == "cowrie.client.kex":
            h = str(e.get("hassh", "") or "")
            if h:
                for a in aggs:
                    a.hassh[h] += 1
                self.reg.add("hassh", h, ts, sensor, "ssh-client-fingerprint", ip)
        elif eid == "cowrie.direct-tcpip.request":
            dst = "%s:%s" % (e.get("dst_ip", "?"), e.get("dst_port", "?"))
            for a in aggs:
                a.tunnels[dst] += 1
            if r is not None:
                r["tags"].add("tunnel-abuse")
            self._att(r, sensor, "T1090")
        elif eid == "cowrie.session.closed":
            d = e.get("duration")
            try:
                d = float(d)
                for a in aggs:
                    a.dur_sum += d
                    a.dur_n += 1
            except (TypeError, ValueError):
                pass

    # ---- Conpot (JSON logger) ---------------------------------------------- #
    def conpot_json(self, e, sensor):
        ts = parse_ts(e.get("timestamp"))
        for k in ("dst_ip", "public_ip"):
            if e.get(k):
                self.self_ips.add(str(e[k]))  # learn our own IPs even outside the window
        if not self._window(ts):
            self.out_of_range += 1
            return
        ip = str(e.get("src_ip") or "")
        if ip and self.ipf.blocked(ip):
            self.excluded += 1
            return
        dtype = str(e.get("data_type") or "unknown").lower()
        etype = str(e.get("event_type") or "data")
        aggs = self._aggs(sensor)
        for a in aggs:
            a.base(ts, ip, "%s %s" % (dtype, etype.lower()))
            a.honeypots["conpot"] += 1
        if ts:
            self.series[sensor][ts.strftime("%Y-%m-%dT%H")] += 1
        sid = e.get("id")
        new_conn = etype.upper() == "NEW_CONNECTION"
        per = aggs[0]
        if sid is not None and sid not in per.session_ids:
            per.session_ids.add(sid)
            new_conn = True
        if new_conn:
            for a in aggs:
                a.sessions += 1
                a.protocols[dtype] += 1
                if e.get("dst_port") is not None:
                    a.ports[e.get("dst_port")] += 1
        req = e.get("request")
        exploit = False
        if req not in (None, "", {}, []):
            text = req if isinstance(req, str) else json.dumps(req, sort_keys=True, default=str)
            exploit = is_exploit(text)
            for a in aggs:
                a.requests["%s: %s" % (dtype, short(text, 140))] += 1
            self._urls(text, ts, sensor, ip, "exploit-payload" if exploit else "seen-in-ics-request", aggs)
        if ip:
            r = self.reg.ip(ip, ts, sensor)
            r["protos"].add(dtype)
            if exploit:
                r["tags"].add("exploit-attempt")
                self._att(r, sensor, "T1190", "T1105")
            if str(dtype).lower() in ICS_PROTOCOLS or dtype in ICS_PROTOCOLS:
                r["tags"].add("ics-scan")
                self._att(r, sensor, "T0846")

    # ---- Conpot (text log, best effort) ------------------------------------ #
    def conpot_text(self, line, sensor):
        own = CONPOT_OWN_IP_RE.search(line)
        if own:
            self.self_ips.add(own.group(1))  # "Fetched 1.2.3.4 as external ip."
            return
        m = TS_RE.search(line)
        if not m:
            return
        rest = line[m.end():]
        ipm = IPV4_RE.search(rest)
        if not ipm:
            return
        low = rest.lower()
        proto = next((p for k, p in CONPOT_PROTOS if k in low), None)
        is_new = bool(re.search(r"\bnew\b.*\b(connection|session)\b", low))
        if proto is None and not is_new:
            return
        ts = parse_ts(m.group(1))
        if not self._window(ts):
            self.out_of_range += 1
            return
        ip = ipm.group(1)
        if self.ipf.blocked(ip):
            self.excluded += 1
            return
        proto = proto or "unknown"
        aggs = self._aggs(sensor)
        for a in aggs:
            a.base(ts, ip, "%s %s" % (proto, "new connection" if is_new else "traffic"))
            a.honeypots["conpot"] += 1
        if ts:
            self.series[sensor][ts.strftime("%Y-%m-%dT%H")] += 1
        if is_new:
            for a in aggs:
                a.sessions += 1
                a.protocols[proto] += 1
        else:
            hm = CONPOT_HTTP_REQ_RE.search(rest)
            detail = None
            if hm:  # "HTTP/1.1 GET request from ('1.2.3.4', 49008): ('/path', ...). <session>"
                detail = "%s %s" % (hm.group(1), hm.group(2))
            elif not CONPOT_RESPONSE_RE.search(rest):
                d = rest[ipm.end():].lstrip(" :'),")
                d = CONPOT_SESSION_RE.sub("", d).strip(" .")
                detail = d or None
            if detail:
                for a in aggs:
                    a.requests["%s: %s" % (proto, short(detail, 140))] += 1
                self._urls(detail, ts, sensor, ip,
                           "exploit-payload" if is_exploit(detail) else "seen-in-ics-request", aggs)
        r = self.reg.ip(ip, ts, sensor)
        r["protos"].add(proto)
        if not is_new and detail and is_exploit(detail):
            r["tags"].add("exploit-attempt")
            self._att(r, sensor, "T1190", "T1105")
        if proto in ICS_PROTOCOLS:
            r["tags"].add("ics-scan")
            self._att(r, sensor, "T0846")

    # ---- Driver ----------------------------------------------------------- #
    def _file_digest(self, path):
        h = hashlib.sha256()
        with open_text(path) as fh:
            for chunk in iter(lambda: fh.read(1 << 20), ""):
                h.update(chunk.encode("utf-8", "replace"))
        return h.hexdigest()

    def parse_file(self, path, kind, sensor, hp=None):
        """Parse one file. Returns the number of lines handled, or None if it was a duplicate copy.

        dedupe="line": skip lines already seen in an earlier file of the same sensor (handles
                       partially overlapping copies; costs ~60 bytes of RAM per line).
        dedupe="file": skip files whose content is identical to one already read (e.g. x and x.gz).
        dedupe="off":  read everything.
        """
        line_mode = self.dedupe == "line"
        fmt = ADAPTERS[kind].fmt if kind in ADAPTERS else "json"
        ctx = {"path": str(path), "hp": hp}
        file_hashes = set()  # hashes of this file's lines, merged into _seen afterwards
        n = 0
        try:
            if self.dedupe == "file":
                digest = self._file_digest(path)
                if digest in self._digests[sensor]:
                    self.dupe_files += 1
                    return None
                self._digests[sensor].add(digest)
            prior = self._seen[sensor]
            with open_text(path) as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    if line_mode:
                        h = hash(line)
                        if h in prior:
                            self.dupes += 1
                            continue
                        file_hashes.add(h)
                    if kind == "conpot-text":
                        self.conpot_text(line, sensor)
                        n += 1
                        continue
                    if fmt in ("text", "csv"):
                        rec = line
                    elif fmt == "pyrepr":
                        rec = _pyrepr(line)
                        if rec is None:
                            try:
                                rec = json.loads(line)
                            except ValueError:
                                self.bad_lines += 1
                                continue
                    else:
                        try:
                            rec = json.loads(line)
                        except ValueError:
                            self.bad_lines += 1
                            continue
                    if fmt != "text" and fmt != "csv" and not isinstance(rec, dict):
                        continue
                    try:
                        self.dispatch(kind, rec, sensor, ctx)
                    except (KeyError, TypeError, ValueError, AttributeError, IndexError, csv.Error):
                        self.bad_lines += 1  # a record that doesn't look like what the parser expects
                        continue
                    n += 1
        except READ_ERRORS as exc:
            print("  ! could not read %s: %s" % (path, exc), file=sys.stderr)
        self._seen[sensor] |= file_hashes
        self.files.append({"sensor": sensor, "file": str(path), "kind": kind, "lines": n})
        return n

    def run(self, sensors, conpot_text_too):
        self._seen = defaultdict(set)     # line hashes per sensor (dedupe="line")
        self._digests = defaultdict(set)  # file digests per sensor (dedupe="file")
        for s in sensors:
            files = s["files"]
            has_cp_json = any(k == "conpot-json" for _, k, _ in files)
            for path, kind, hp in files:
                if kind == "conpot-text" and has_cp_json and not conpot_text_too:
                    s["skipped"].append(str(path))
                    continue
                n = self.parse_file(path, kind, s["id"], hp)
                rel = path.relative_to(s["dir"])
                if n is None:
                    print("  %-22s %-14s  duplicate copy, skipped  %s" % (s["id"][:22], hp, rel))
                else:
                    print("  %-22s %-14s %8d lines  %s" % (s["id"][:22], hp, n, rel))
            for sk in s["skipped"]:
                print("  %-22s %-12s  skipped (conpot.json present)  %s" % (s["id"][:22], "conpot-text", Path(sk).name))
            self._aggs(s["id"])
        del self._seen, self._digests
        self._finalize_tags()

    def _finalize_tags(self):
        for ip, r in self.reg.ips.items():
            if r["fail"] >= self.bf:
                r["tags"].add("bruteforce")
            if r["ok"]:
                r["tags"].add("login-success")
            if r["cmds"]:
                r["tags"].add("command-exec")
            if r["dl"]:
                r["tags"].add("malware-download")
            elif r["dl_fail"]:
                r["tags"].add("download-attempt")
            if len(r["sensors"]) > 1:
                r["tags"].add("multi-sensor")
            if r["events"] > 0 and not (r["tags"] - INFO_TAGS) and not r["fail"]:
                r["tags"].add("scanner")
                for sensor in r["sensors"]:
                    self._att(r, sensor, "T1595.001")
            elif r["fail"] and r["fail"] < self.bf and not r["ok"]:
                r["tags"].add("login-attempt")


# --------------------------------------------------------------------------- #
# IOC building & export
# --------------------------------------------------------------------------- #

HIGH_TAGS = {"command-exec", "malware-download", "download-attempt", "payload-host",
             "persistence", "privilege-escalation", "cryptomining", "tunnel-abuse", "downloaded",
             "download-failed", "uploaded", "raw-ip-host", "exploit-attempt", "exploit-callback",
             "exploit-payload", "download-url"}
# Informational tags: they describe an IP but don't make it more than a scanner on their own
INFO_TAGS = {"multi-sensor", "voip-scan", "spoofable-udp", "research-scanner"}
# A login alone is medium, not high: Cowrie accepts almost any password, so "logged in" mostly
# means "a bot tried a common password". What happens after the login is what earns "high".
MED_TAGS = {"login-success", "bruteforce", "multi-sensor", "ics-scan", "medical-scan", "web-attack", "seen-in-payload",
            "captured", "defense-evasion", "seen-in-command",
            "seen-in-ics-request", "referenced-host", "multi-source"}
CONF_SCORE = {"high": 85, "medium": 60, "low": 30}
CONF_ORDER = ["low", "medium", "high"]
# Hosts that must never leave your machine inside a URL/domain IOC
LOCAL_ONLY = {"own-sensor", "private-host", "allowlisted"}  # "dynamic-dns" hosts ARE shareable


def confidence(tags):
    if "allowlisted" in tags:
        return "low"
    if tags & HIGH_TAGS:
        return "high"
    if tags & MED_TAGS:
        return "medium"
    return "low"


def host_class(host, self_ips, ipf, benign, shared):
    """Classify the host part of a URL/domain IOC. None means 'ordinary, shareable'."""
    h = (host or "").lower().rstrip(".")
    if not h:
        return None
    if h in self_ips:
        return "own-sensor"
    if valid_ip(h):
        return ipf.kind(h)  # "own-sensor" (excluded), "private-host" or None
    if h == "localhost" or h.endswith((".localhost", ".local", ".internal", ".lan", ".home.arpa")):
        return "private-host"
    if domain_in(h, benign):
        return "allowlisted"
    if h in DYNAMIC_DNS:
        return "shared-hosting"   # the platform itself
    if domain_in(h, DYNAMIC_DNS):
        return "dynamic-dns"      # one customer's hostname: shareable
    if domain_in(h, shared):
        return "shared-hosting"
    return None


def build_iocs(an, sensor_name, self_ips, benign, shared, geo=None, keep_research=False, scanners=None):
    """Every IOC, each with a 'shareable' flag. Non-shareable ones only appear in the local dashboard."""
    geo = geo or {}
    iocs = []
    for ip, r in an.reg.ips.items():
        if ip in self_ips:
            continue
        tags = set(r["tags"])
        ctx = []
        if r["fail"] or r["ok"]:
            ctx.append("logins %d failed / %d ok" % (r["fail"], r["ok"]))
        if r["cmds"]:
            ctx.append("%d commands" % r["cmds"])
        if r["dl"]:
            ctx.append("%d file transfers" % r["dl"])
        if r["dl_fail"]:
            ctx.append("%d failed downloads" % r["dl_fail"])
        if r["refs"]:
            ctx.append("payload host in %d URL(s)" % r["refs"])
        if r["protos"]:
            ctx.append("services: " + ", ".join(sorted(r["protos"])[:12]))
        shareable = True
        if RESEARCH_SCANNER_RE.search(str(geo.get(ip, {}).get("as_org", ""))):
            tags.add("research-scanner")
        elif scanners is not None and scanners.contains(ip):
            tags.add("research-scanner")  # in a published scanner range (--scanners / scanners.txt)
        # An IP that only scanned stays low even if it hit several sensors: mass scanners sweep
        # every address, so "seen on more than one sensor" adds nothing about intent.
        conf = confidence(tags - {"multi-sensor"} if "scanner" in tags else tags)
        if "research-scanner" in tags and not keep_research:
            shareable, conf = False, "low"  # Censys, Shadowserver, ONYPHE... benign, known
        if "spoofable-udp" in tags and not (tags & ((HIGH_TAGS | MED_TAGS) - {"multi-sensor"})):
            # Only ever seen by a UDP reflection honeypot: almost certainly a spoofed victim
            tags.add("possibly-spoofed")
            shareable, conf = False, "low"
        iocs.append({
            "type": "ipv4" if ":" not in ip else "ipv6", "value": ip,
            "first_seen": iso(r["first"]), "last_seen": iso(r["last"]),
            "sensors": sorted(sensor_name(s) for s in r["sensors"]),
            "sensor_count": len(r["sensors"]), "count": r["events"] + r["refs"],
            "tags": sorted(tags), "confidence": conf, "context": "; ".join(ctx),
            "country": geo.get(ip, {}).get("cc", ""), "asn": geo.get(ip, {}).get("asn", ""),
            "as_org": geo.get(ip, {}).get("as_org", ""),
            "attack": sorted(set().union(*r["att"].values())) if r["att"] else [],
            "shareable": shareable,
        })
    for (typ, val), r in an.reg.other.items():
        tags = set(r["tags"])
        if len(r["sensors"]) > 1:
            tags.add("multi-sensor")
        if len({source_net(x) for x in r["ips"]}) > 1:
            tags.add("multi-source")  # different /24s: one research cluster trying keys doesn't count
        shareable = True
        if typ in ("url", "domain"):
            try:
                host = urlsplit(val).hostname if typ == "url" else val
            except ValueError:
                host = None
            hc = host_class(host, self_ips, ipf=an.ipf, benign=benign, shared=shared)
            if hc:
                tags.add(hc)
            if hc in LOCAL_ONLY or (typ == "domain" and hc == "shared-hosting"):
                shareable = False
        iocs.append({
            "type": typ, "value": val,
            "first_seen": iso(r["first"]), "last_seen": iso(r["last"]),
            "sensors": sorted(sensor_name(s) for s in r["sensors"]),
            "sensor_count": len(r["sensors"]), "count": r["count"],
            # HASSH fingerprints a client library, which legitimate tools share: context, never a block
            # SSH keys: medium only when sources in different networks share one (an operator's key)
            "tags": sorted(tags), "confidence": "low" if typ == "hassh" else
            ("medium" if "multi-source" in tags else "low") if typ == "ssh-key" else confidence(tags),
            "context": "%d source IP(s)" % len(r["ips"]) if r["ips"] else "",
            "country": "", "asn": "", "as_org": "",
            "attack": (["T1190"] if tags & {"exploit-callback", "exploit-payload"} else []) +
                      (["T1105"] if tags & {"downloaded", "download-failed", "uploaded", "payload-host",
                                            "captured", "raw-ip-host", "exploit-payload",
                                            "download-url"} else []),
            "shareable": shareable,
        })
    rank = {"high": 0, "medium": 1, "low": 2}
    tord = {"sha256": 0, "url": 1, "domain": 2, "ipv4": 3, "ipv6": 4, "ssh-key": 5, "hassh": 6}
    iocs.sort(key=lambda i: (not i["shareable"], tord.get(i["type"], 9), rank[i["confidence"]],
                             -i["count"], i["value"]))
    return iocs


# --------------------------------------------------------------------------- #
# State between runs
# --------------------------------------------------------------------------- #

class State:
    """Remembers IOC first/last seen, STIX object versions and the anonymisation salt."""

    FORMAT = 1

    def __init__(self, path):
        self.path = path
        self.data = {"format": self.FORMAT, "tool": TOOL, "salt": secrets.token_hex(16),
                     "iocs": {}, "stix": {}}
        self.loaded = False
        if path and path.is_file():
            try:
                d = json.loads(path.read_text(encoding="utf-8"))
                if not isinstance(d, dict) or d.get("format") != self.FORMAT:
                    raise ValueError("unrecognised state format")
            except (OSError, ValueError) as exc:
                # Starting over silently would hand TAXII consumers new `created` values for
                # objects they already have, so stop and let the user decide.
                raise SystemExit("State file %s is unreadable (%s).\nFix or move it, or run with "
                                 "--no-state." % (path, exc))
            self.data.update(d)
            self.loaded = True

    @property
    def salt(self):
        return self.data["salt"]

    def merge_seen(self, iocs):
        """Widen first/last seen to everything ever observed, so --days doesn't rewrite history."""
        store = self.data["iocs"]
        for i in iocs:
            key = "%s|%s" % (i["type"], i["value"])
            old = store.get(key, {})
            firsts = [t for t in (old.get("first"), i["first_seen"]) if t]
            lasts = [t for t in (old.get("last"), i["last_seen"]) if t]
            i["first_seen"] = min(firsts) if firsts else ""
            i["last_seen"] = max(lasts) if lasts else ""
            store[key] = {"first": i["first_seen"], "last": i["last_seen"]}

    def stix_version(self, sid, digest, now):
        """(created, modified) for a STIX object: created never changes, modified moves only
        when the object's content does."""
        store = self.data["stix"]
        old = store.get(sid)
        if old is None:
            created = modified = now
        elif old["digest"] == digest:
            created, modified = old["created"], old["modified"]
        else:
            created, modified = old["created"], max(now, old["modified"])
        store[sid] = {"created": created, "modified": modified, "digest": digest}
        return created, modified

    def save(self):
        if not self.path:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_name(self.path.name + ".tmp")
        tmp.write_text(json.dumps(self.data, separators=(",", ":")), encoding="utf-8")
        os.replace(str(tmp), str(self.path))


def default_state_path(root=None):
    """One state file for every run: log pulls often land in a new folder each time
    (1113_2058, 1113_2155, ...) and they are all the same feed."""
    return Path.home() / ".honeycomb" / "state.json"


def source_net(ip):
    """IPv4 /24 or IPv6 /48 - sources inside one of these count as one for multi-source."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    return str(ipaddress.ip_network("%s/%d" % (addr, 24 if addr.version == 4 else 48), strict=False))


def ssh_key_fingerprint(key):
    """'ssh-ed25519 AAAA... comment' -> 'SHA256:...' as ssh-keygen -l prints it, or '' if unparsable."""
    parts = str(key or "").split()
    if len(parts) < 2:
        return ""
    try:
        blob = base64.b64decode(parts[1], validate=True)
    except (binascii.Error, ValueError):
        return ""
    if len(blob) < 16:
        return ""
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")


# --------------------------------------------------------------------------- #
# Exports
# --------------------------------------------------------------------------- #

CSV_DANGEROUS = ("=", "+", "-", "@", "\t", "\r")


def csv_safe(v):
    """Neutralise spreadsheet formula injection (attacker-controlled strings)."""
    s = "" if v is None else str(v)
    return "'" + s if s.startswith(CSV_DANGEROUS) else s


def write_csv(path, header, rows):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        for row in rows:
            w.writerow([csv_safe(c) for c in row])


TLP = {  # STIX 2.1 predefined TLP marking definitions
    "clear": ("marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9", "white"),
    "green": ("marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da", "green"),
    "amber": ("marking-definition--f88d31f6-486f-44da-b317-01333bde0b82", "amber"),
    "red": ("marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed", "red"),
}
STIX_NS = uuid.UUID("6f1c2d6e-8b1e-4c55-9d0b-9a7a8f3e2b11")  # unchanged: keeps indicator IDs stable
IDENTITY_CREATED = "2026-01-01T00:00:00.000Z"                # fixed: identity `created` must not move


def stix_str(s):
    return str(s).replace("\\", "\\\\").replace("'", "\\'")


def stix_ts(value):
    """STIX 2.1 wants created/modified to millisecond precision: 2026-11-07T10:00:00.000Z"""
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + \
            "%03dZ" % (value.microsecond // 1000)
    dt = parse_ts(value)
    return stix_ts(dt) if dt else ""


def stix_bundle(iocs, org, tlp, state=None, valid_days=30):
    now_dt = datetime.now(timezone.utc)
    now = stix_ts(now_dt)
    ident_id = "identity--" + str(uuid.uuid5(STIX_NS, "identity:" + org))
    mid, tlp_name = TLP[tlp]
    objs = [
        {"type": "marking-definition", "spec_version": "2.1", "id": mid,
         "created": "2017-01-20T00:00:00.000Z", "definition_type": "tlp",
         "name": "TLP:" + tlp_name.upper(), "definition": {"tlp": tlp_name}},
        {"type": "identity", "spec_version": "2.1", "id": ident_id, "created": IDENTITY_CREATED,
         "modified": IDENTITY_CREATED, "name": org, "identity_class": "individual"},
    ]
    patterns = {
        "ipv4": "[ipv4-addr:value = '%s']", "ipv6": "[ipv6-addr:value = '%s']",
        "url": "[url:value = '%s']", "domain": "[domain-name:value = '%s']",
        "sha256": "[file:hashes.'SHA-256' = '%s']",
    }
    patterns_added = set()
    for i in iocs:
        if i["type"] not in patterns:
            continue  # HASSH and SSH key fingerprints have no standard STIX observable
        pattern = patterns[i["type"]] % stix_str(i["value"])
        sid = "indicator--" + str(uuid.uuid5(STIX_NS, pattern))
        first_dt = parse_ts(i["first_seen"]) or now_dt
        last_dt = max(parse_ts(i["last_seen"]) or now_dt, first_dt)
        kind = "malicious-activity" if i["confidence"] == "high" else "anomalous-activity"
        body = {
            "created_by_ref": ident_id,
            "name": "Honeypot %s: %s" % (i["type"], i["value"]),
            "description": "Observed by %d honeypot sensor(s). Tags: %s. %s" % (
                i["sensor_count"], ", ".join(i["tags"]) or "none", i["context"]),
            "indicator_types": [kind], "pattern": pattern, "pattern_type": "stix",
            "valid_from": stix_ts(first_dt), "confidence": CONF_SCORE[i["confidence"]],
            "labels": i["tags"], "object_marking_refs": [mid],
        }
        geo_bits = [x for x in (i.get("country"), ("AS%s %s" % (i["asn"], i.get("as_org", ""))).strip()
                                if i.get("asn") else "") if x]
        if geo_bits:
            body["description"] += " Geo: %s." % ", ".join(geo_bits)
        techs = [t for t in i.get("attack", []) if t in ATTACK]
        if techs:
            phases = []
            for t in techs:
                ph = {"kill_chain_name": "mitre-ics-attack" if t.startswith("T0") else "mitre-attack",
                      "phase_name": ATTACK[t][1]}
                if ph not in phases:
                    phases.append(ph)
            body["kill_chain_phases"] = phases
        if valid_days > 0:
            # Honeypot IPs go stale fast; tell consumers when to stop trusting this.
            body["valid_until"] = stix_ts(last_dt + timedelta(days=valid_days))
        if state is not None:
            digest = hashlib.sha256(json.dumps(body, sort_keys=True).encode("utf-8")).hexdigest()
            created, modified = state.stix_version(sid, digest, now)
        else:
            # Without state we can only approximate; `created` may shift if first_seen does.
            created, modified = stix_ts(first_dt), now
        obj = {"type": "indicator", "spec_version": "2.1", "id": sid,
               "created": created, "modified": modified}
        obj.update(body)
        objs.append(obj)
        for t in techs:
            # one attack-pattern per technique, linked with an "indicates" relationship
            ap_id = "attack-pattern--" + str(uuid.uuid5(STIX_NS, "attack-pattern:" + t))
            if ap_id not in patterns_added:
                patterns_added.add(ap_id)
                ics = t.startswith("T0")
                objs.append({
                    "type": "attack-pattern", "spec_version": "2.1", "id": ap_id,
                    "created": IDENTITY_CREATED, "modified": IDENTITY_CREATED, "created_by_ref": ident_id,
                    "name": ATTACK[t][0], "object_marking_refs": [mid],
                    "kill_chain_phases": [{"kill_chain_name": "mitre-ics-attack" if ics else "mitre-attack",
                                           "phase_name": ATTACK[t][1]}],
                    "external_references": [{"source_name": "mitre-ics-attack" if ics else "mitre-attack",
                                             "external_id": t, "url": attack_url(t)}]})
            objs.append({
                "type": "relationship", "spec_version": "2.1",
                "id": "relationship--" + str(uuid.uuid5(STIX_NS, "indicates:%s:%s" % (sid, t))),
                "created": created, "modified": created, "created_by_ref": ident_id,
                "relationship_type": "indicates", "source_ref": sid, "target_ref": ap_id,
                "object_marking_refs": [mid]})
    return {"type": "bundle", "id": "bundle--" + str(uuid.uuid4()), "objects": objs}


# --------------------------------------------------------------------------- #
# Sensor discovery
# --------------------------------------------------------------------------- #

def discover(root, cfg, out=None):
    scfg = cfg.get("sensors", {})
    sensors = []
    dirs = sorted((p for p in root.iterdir() if p.is_dir() and not p.name.startswith(".")),
                  key=lambda p: (list(scfg).index(p.name) if p.name in scfg else len(scfg), p.name.lower()))
    for d in dirs:
        if out is not None and d.resolve() == out:
            continue  # our own report folder, if --out points inside the log root
        conf = scfg.get(d.name, {})
        if conf.get("skip"):
            continue
        files = []
        forced = str(conf.get("type") or "").lower() or None
        for f in sorted(d.rglob("*")):
            if not f.is_file():
                continue
            parts = [x.lower() for x in f.relative_to(d).parts[:-1]]
            if any(x in SKIP_DIRS or x in TPOT_SKIP_DIRS for x in parts):
                continue  # captured malware, tty recordings, T-Pot's IDS / web UI logs
            # T-Pot layout (<honeypot>/log/<file>) tells us which honeypot wrote a file
            hint = next((HINTS[x] for x in reversed(parts) if x in HINTS), None)
            if hint is None:
                hint = HINTS.get(forced or "") or HINTS.get(d.name.lower())
            kind = classify(f, hint)
            if not kind:
                continue
            if kind == "generic":
                hp = next((x for x in reversed(parts) if x not in ("log", "logs", "data", "var")), None) \
                    or forced or d.name.lower()
            else:
                hp = KIND_HP.get(kind, kind)
            if forced and hp != forced and kind != "tpot-es":
                continue
            files.append((f, kind, hp))
        if not files:
            print("  (skipping %s: no honeypot logs found)" % d.name)
            continue
        kinds = sorted({hp for _, _, hp in files})
        sensors.append({
            "id": d.name, "label": conf.get("label", d.name),
            "public_name": conf.get("public_name", d.name),
            "location": conf.get("location", ""), "kinds": kinds,
            "files": files, "skipped": [], "dir": d,
        })
    return sensors


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

def parse_date(s):
    try:
        return datetime.strptime(s, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        raise argparse.ArgumentTypeError("use YYYY-MM-DD")


def load_domain_list(lines):
    out = set()
    for line in lines:
        d = str(line).split("#", 1)[0].strip().lower().rstrip(".")
        if d.startswith("*."):
            d = d[2:]
        d = d.lstrip(".")
        if d:
            out.add(d)
    return out


def export_names(sensors, anonymize, salt):
    """Map sensor id -> name used in exports. Anonymised names are derived from a secret salt,
    so they stay the same when you add or remove sensors and can't be reversed."""
    names, used = {}, set()
    for idx, s in enumerate(sensors):
        if anonymize and salt:
            base = "sensor-" + hashlib.sha256((salt + "|" + s["id"]).encode("utf-8")).hexdigest()[:6]
        elif anonymize:
            base = "sensor-" + chr(65 + idx % 26) + (str(idx // 26) if idx >= 26 else "")
        else:
            base = s["public_name"]
        name, n = base, 2
        while name in used:
            name, n = "%s-%d" % (base, n), n + 1
        used.add(name)
        names[s["id"]] = name
    return names


def redact_ips(text, ips):
    """Replace literal occurrences of our own IPs (with sane boundaries) in a string."""
    ips = sorted({i for i in ips if valid_ip(i)}, key=len, reverse=True)
    if not ips:
        return text
    rx = re.compile(r"(?<![\w.:])(?:%s)(?![\w:]|\.\d)" % "|".join(re.escape(i) for i in ips))
    return rx.sub("[sensor-ip]", text)


def use_color(disabled):
    if disabled or os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        return False
    return _enable_ansi()


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="honeycomb",
        description="HONEYCOMB - combs through honeypot logs (Cowrie, Conpot, MedPot and everything "
                    "T-Pot runs) from many sensors and "
                    "builds an offline dashboard plus shareable IOC feeds (CSV, JSON, STIX 2.1).")
    ap.add_argument("root", help="folder containing one child folder per sensor")
    ap.add_argument("--out", default="honeycomb-report", help="output folder (default: ./honeycomb-report)")
    ap.add_argument("--since", type=parse_date, help="only events on/after YYYY-MM-DD 00:00 UTC")
    ap.add_argument("--until", type=parse_date,
                    help="only events before YYYY-MM-DD 00:00 UTC (exclusive: --until 2026-11-10 "
                         "stops at the end of the 9th)")
    ap.add_argument("--days", type=int, help="only the last N days (overrides --since)")
    ap.add_argument("--exclude", action="append", default=[],
                    help="IP or CIDR to ignore (your own IPs). Repeatable / comma-separated")
    ap.add_argument("--include-private", action="store_true",
                    help="keep RFC1918/loopback/reserved source IPs (dropped by default)")
    ap.add_argument("--allowlist", action="append", default=[], metavar="FILE",
                    help="file of benign domains (one per line, subdomains match) never exported")
    ap.add_argument("--bruteforce-threshold", type=int, default=5,
                    help="failed logins from one IP before tagging bruteforce (default 5)")
    ap.add_argument("--min-confidence", choices=CONF_ORDER, default="low",
                    help="lowest confidence written to the shareable IOC exports")
    ap.add_argument("--anonymize-sensors", action="store_true",
                    help="replace sensor names with stable random-looking names (sensor-3fa9c1) in exports")
    ap.add_argument("--public", action="store_true",
                    help="make dashboard.html safe to publish: no local paths, export names only, "
                         "only shareable IOCs, your sensor IPs redacted")
    ap.add_argument("--tlp", choices=list(TLP), default="clear", help="TLP marking for STIX (default clear)")
    ap.add_argument("--org", default=TOOL, help="producer name for the STIX identity (default %s)" % TOOL)
    ap.add_argument("--valid-days", type=int, default=30,
                    help="STIX valid_until = last seen + N days (default 30, 0 = no expiry)")
    ap.add_argument("--state", metavar="FILE",
                    help="state file kept between runs (default ~/.honeycomb/state.json, shared by all runs)")
    ap.add_argument("--no-state", action="store_true",
                    help="don't read or write a state file (STIX versioning becomes approximate)")
    ap.add_argument("--dedupe", choices=["line", "file", "off"], default="line",
                    help="line: drop identical lines across overlapping copies (default, ~60 B RAM per "
                         "line); file: only skip identical files (low memory); off")
    ap.add_argument("--geoip", action="append", default=[], metavar="FILE",
                    help="GeoIP/ASN database: .mmdb (GeoLite2, DB-IP Lite, IPinfo Lite) or DB-IP/IP2Location "
                         ".csv[.gz]. Repeatable (e.g. City + ASN). Files in ~/.honeycomb/ are used automatically")
    ap.add_argument("--no-geo", action="store_true", help="skip country/ASN lookups")
    ap.add_argument("--scanners", action="append", default=[], metavar="FILE",
                    help="file of research-scanner IPs/CIDRs held back from exports (one per line, # comments). "
                         "Repeatable. scanners.txt next to honeycomb.py is used automatically")
    ap.add_argument("--no-scanner-list", action="store_true",
                    help="don't load the bundled scanners.txt")
    ap.add_argument("--keep-research-scanners", action="store_true",
                    help="export research scanners too (recognised by ASN name with --geoip, or by "
                         "the --scanners / scanners.txt ranges; held back by default)")
    ap.add_argument("--conpot-text-too", action="store_true",
                    help="also parse conpot.log when conpot.json exists (may double count)")
    ap.add_argument("--no-banner", action="store_true", help="don't print the banner")
    ap.add_argument("--no-color", action="store_true", help="no ANSI colours (also honours NO_COLOR)")
    ap.add_argument("--version", action="version", version="%s %s" % (TOOL, VERSION))
    args = ap.parse_args(argv)

    if not args.no_banner:
        print_banner(use_color(args.no_color))

    root = Path(args.root).expanduser().resolve()
    if not root.is_dir():
        ap.error("%s is not a folder" % root)
    cfg = {}
    cfg_path = root / "sensors.json"
    if cfg_path.is_file():
        try:
            cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
        except ValueError as exc:
            ap.error("sensors.json is not valid JSON: %s" % exc)
        if not isinstance(cfg, dict) or not isinstance(cfg.get("sensors", {}), dict):
            ap.error('sensors.json must be an object like {"sensors": {...}, "exclude": [...]}')

    nets = []
    for item in list(args.exclude) + list(cfg.get("exclude", [])):
        for part in str(item).split(","):
            part = part.strip()
            if part:
                try:
                    nets.append(ipaddress.ip_network(part, strict=False))
                except ValueError:
                    ap.error("bad --exclude value: %s" % part)

    benign = set(BENIGN_DOMAINS) | load_domain_list(cfg.get("allowlist", []))
    for f in args.allowlist:
        try:
            benign |= load_domain_list(Path(f).expanduser().read_text(encoding="utf-8").splitlines())
        except OSError as exc:
            ap.error("can't read --allowlist %s: %s" % (f, exc))

    if args.public and not args.anonymize_sensors:
        print("  ! --public without --anonymize-sensors: sensor folder names (or public_name from "
              "sensors.json) will appear in the dashboard", file=sys.stderr)

    state = None
    if not args.no_state:
        state = State(Path(args.state).expanduser().resolve() if args.state else default_state_path(root))
    elif args.anonymize_sensors:
        print("  ! --no-state: anonymised names fall back to sensor-A, sensor-B... which change "
              "if you add sensors", file=sys.stderr)

    since = args.since
    if args.days:
        since = datetime.now(timezone.utc) - timedelta(days=args.days)

    out = Path(args.out).expanduser().resolve()
    print("Scanning %s" % root)
    sensors = discover(root, cfg, out)
    if not sensors:
        print("No sensors with recognised honeypot logs found under %s (one child folder per sensor)" % root)
        return 1

    geodb = None
    if not args.no_geo:
        geo_files = [Path(f).expanduser() for f in args.geoip] or find_geo_dbs(root)
        if geo_files:
            try:
                geodb = GeoDB(geo_files)
                print("GeoIP:    " + ", ".join(geodb.names))
            except (OSError, ValueError, KeyError) as exc:
                ap.error("can't load GeoIP database: %s" % exc)

    scanner_files = [Path(f).expanduser() for f in args.scanners]
    bundled = Path(__file__).resolve().with_name("scanners.txt")
    if not args.no_scanner_list and bundled.is_file() and bundled not in [f.resolve() for f in scanner_files]:
        scanner_files.insert(0, bundled)
    scanners = ScannerList()
    for f in scanner_files:
        try:
            scanners.load(f.read_text(encoding="utf-8").splitlines(), f.name)
        except OSError as exc:
            ap.error("can't read --scanners %s: %s" % (f, exc))
    scanners.load(cfg.get("scanners", []), "sensors.json")
    if scanners.count:
        print("Scanners: %d ranges (%s)%s" % (scanners.count, ", ".join(scanners.sources),
              "  ! %d unreadable lines ignored" % scanners.bad if scanners.bad else ""))

    ipf = IPFilter(nets, args.include_private)
    an = Analyzer(ipf, since, args.until, args.bruteforce_threshold, args.dedupe)
    an.run(sensors, args.conpot_text_too)

    # Our own addresses: learned from the logs plus single-host --exclude entries
    self_ips = set(an.self_ips) | {str(n.network_address) for n in nets if n.num_addresses == 1}

    names = export_names(sensors, args.anonymize_sensors, state.salt if state else None)
    # Geo for every attacker / payload-host IP: local DB first, then what T-Pot already attached
    geo = {}
    for ip in an.reg.ips:
        g = dict(geodb.lookup(ip)) if geodb else {}
        for k, v in an.es_geo.get(ip, {}).items():
            g.setdefault(k, v)
        if g:
            geo[ip] = g
    iocs = build_iocs(an, lambda sid: names.get(sid, sid), self_ips, benign, SHARED_HOSTING, geo,
                      args.keep_research_scanners, scanners)
    if state is not None:
        state.merge_seen(iocs)

    # overlap between sensors
    cross = []
    for ip, r in an.reg.ips.items():
        if len(r["sensors"]) > 1 and r["events"] > 0 and ip not in self_ips:
            cross.append({"ip": ip, "sensors": sorted(r["sensors"]), "events": r["events"],
                          "first": iso(r["first"]), "last": iso(r["last"]), "tags": sorted(r["tags"])})
    cross.sort(key=lambda c: (-len(c["sensors"]), -c["events"]))

    (out / "iocs").mkdir(parents=True, exist_ok=True)

    floor = CONF_ORDER.index(args.min_confidence)
    share = [i for i in iocs if i["shareable"] and CONF_ORDER.index(i["confidence"]) >= floor]
    clean = [{k: v for k, v in i.items() if k != "shareable"} for i in share]
    write_csv(out / "iocs" / "master_iocs.csv",
              ["type", "value", "confidence", "first_seen", "last_seen", "sensor_count", "sensors",
               "count", "tags", "attack", "country", "asn", "as_org", "context"],
              ([i["type"], i["value"], i["confidence"], i["first_seen"], i["last_seen"],
                i["sensor_count"], ";".join(i["sensors"]), i["count"], ";".join(i["tags"]),
                ";".join(i["attack"]), i["country"], i["asn"], i["as_org"], i["context"]]
               for i in clean))
    (out / "iocs" / "master_iocs.json").write_text(json.dumps({
        "generated": iso(datetime.now(timezone.utc)), "producer": args.org, "tool": "%s %s" % (TOOL, VERSION),
        "tlp": args.tlp, "count": len(clean), "iocs": clean}, indent=2), encoding="utf-8")
    (out / "iocs" / "stix2_bundle.json").write_text(
        json.dumps(stix_bundle(clean, args.org, args.tlp, state, args.valid_days), indent=2),
        encoding="utf-8")
    for typ, fname in (("ipv4", "ipv4.txt"), ("ipv6", "ipv6.txt"), ("url", "urls.txt"),
                       ("domain", "domains.txt"), ("sha256", "sha256.txt"), ("hassh", "hassh.txt"),
                       ("ssh-key", "ssh_keys.txt")):
        vals = [i["value"] for i in clean if i["type"] == typ]
        (out / "iocs" / fname).write_text("\n".join(vals) + ("\n" if vals else ""), encoding="utf-8")
    write_csv(out / "credentials.csv", ["sensor", "username", "password", "success", "count"],
              ([names.get(s, s), u, p, "yes" if ok else "no", n]
               for (s, u, p, ok), n in an.creds.most_common()))
    # Exact values for wordlists: the CSV above is escaped for spreadsheets, this is not.
    with open(out / "credentials.jsonl", "w", encoding="utf-8", newline="\n") as fh:
        for (s, u, p, ok), n in an.creds.most_common():
            fh.write(json.dumps({"sensor": names.get(s, s), "username": u, "password": p,
                                 "success": bool(ok), "count": n}, ensure_ascii=False) + "\n")

    # dashboard payload
    pub = (lambda sid: names.get(sid, sid)) if args.public else (lambda sid: sid)
    files = an.files
    if args.public:
        files = [{"sensor": f["sensor"], "file": Path(f["file"]).name, "kind": f["kind"],
                  "lines": f["lines"]} for f in an.files]
    payload = {
        "meta": {
            "tool": TOOL, "version": VERSION, "generated": iso(datetime.now(timezone.utc)),
            "root": "" if args.public else str(root), "out": "" if args.public else str(out),
            "since": iso(since), "until": iso(args.until), "excluded_events": an.excluded,
            "out_of_range": an.out_of_range, "bad_lines": an.bad_lines, "duplicate_lines": an.dupes,
            "duplicate_files": an.dupe_files, "public": args.public, "no_source": an.no_source,
            "files": [dict(f, sensor=pub(f["sensor"])) for f in files],
            "min_confidence": args.min_confidence, "tlp": args.tlp,
        },
        "sensors": [{
            "id": pub(s["id"]), "label": names[s["id"]] if args.public else s["label"],
            "location": "" if args.public else s["location"], "kinds": s["kinds"],
            "export_name": names[s["id"]],
            "skipped": [Path(p).name for p in s["skipped"]] if args.public else s["skipped"],
            "stats": an.per[s["id"]].stats(),
        } for s in sensors],
        "overview": an.total.stats(),
        "series": {pub(sid): sorted([k, v] for k, v in c.items()) for sid, c in an.series.items()},
        "cross": [dict(c, sensors=[pub(x) for x in c["sensors"]]) for c in cross[:500]],
        "cross_total": len(cross),
        "iocs": clean if args.public else iocs,
    }
    def extra(agg, sensor=None):
        """Countries, networks and ATT&CK techniques for one view."""
        cc_ev, cc_ip, asn_ev = Counter(), Counter(), Counter()
        for ip, n in agg.ips.items():
            g = geo.get(ip, {})
            if g.get("cc"):
                cc_ev[g["cc"]] += n
                cc_ip[g["cc"]] += 1
            if g.get("asn"):
                asn_ev["AS%s %s" % (g["asn"], g.get("as_org", ""))] += n
        tech = Counter()
        for ip, r in an.reg.ips.items():
            ts_ = (set().union(*r["att"].values()) if r["att"] else set()) if sensor is None \
                else r["att"].get(sensor, set())
            for t in ts_:
                tech[t] += 1
        return {"countries": [[c, n, cc_ip[c]] for c, n in cc_ev.most_common(25)],
                "asns": [[k.strip(), n] for k, n in asn_ev.most_common(TOP_N)],
                "attack": [[t, n] for t, n in tech.most_common()]}
    payload["overview"].update(extra(an.total))
    for s_out, s in zip(payload["sensors"], sensors):
        s_out["stats"].update(extra(an.per[s["id"]], s["id"]))
    payload["attack_ref"] = {t: [n, tac] for t, (n, tac) in ATTACK.items()}
    payload["tactics"] = TACTIC_ORDER
    shown = {i["value"] for i in payload["iocs"] if i["type"] in ("ipv4", "ipv6")}
    payload["geo"] = {ip: [g.get("cc", ""), g.get("asn", ""), g.get("as_org", ""), g.get("city", "")]
                      for ip, g in geo.items() if ip in shown or not args.public}
    payload["meta"]["geo_source"] = (", ".join(geodb.names) if geodb else "") + \
        (("; " if geodb else "") + "T-Pot export" if an.es_geo else "")
    blob = json.dumps(payload, ensure_ascii=True, separators=(",", ":"))
    if args.public:
        blob = redact_ips(blob, self_ips)
    blob = blob.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    (out / "dashboard.html").write_text(HTML.replace("__DATA__", blob), encoding="utf-8")

    if state is not None:
        state.save()

    k = an.total.stats()["kpi"]
    by_type = Counter(i["type"] for i in clean)
    held = sum(1 for i in iocs if not i["shareable"])
    print("\nEvents: %d  Unique IPs: %d  Sessions: %d  Logins: %d (%d ok)  Commands: %d" % (
        k["events"], k["unique_ips"], k["sessions"], k["login_attempts"], k["login_success"], k["commands"]))
    print("IPs seen on more than one sensor: %d" % len(cross))
    ov = payload["overview"]
    if ov["countries"]:
        print("Top countries: " + ", ".join("%s %d" % (c, n) for c, n, _ in ov["countries"][:8]))
    elif not args.no_geo:
        print("Top countries: (no GeoIP data - see --geoip)")
    if ov["attack"]:
        print("Top ATT&CK:    " + ", ".join("%s %d" % (t, n) for t, n in ov["attack"][:6]))
    print("IOCs exported (>= %s confidence): %d  %s" % (
        args.min_confidence, len(clean), ", ".join("%s=%d" % kv for kv in sorted(by_type.items()))))
    print("Held back (own sensor / private / allowlisted / shared-hosting domain / research scanner / "
          "possibly spoofed): %d" % held)
    print("Ignored: %d excluded/private-IP events, %d outside date range, %d duplicate lines, "
          "%d duplicate files, %d bad lines, %d records without a source IP" % (
              an.excluded, an.out_of_range, an.dupes, an.dupe_files, an.bad_lines, an.no_source))
    if an.skipped_types:
        print("Skipped T-Pot export records that aren't honeypot sessions: %s" % ", ".join(
            "%s=%d" % kv for kv in an.skipped_types.most_common()))
    print("\nDashboard: %s%s" % (out / "dashboard.html", "  (public mode)" if args.public else ""))
    print("IOCs:      %s" % (out / "iocs"))
    if state is not None:
        print("State:     %s%s" % (state.path, "" if state.loaded else "  (new)"))
    return 0


# --------------------------------------------------------------------------- #
# Dashboard template (self-contained; all data rendered with textContent)
# --------------------------------------------------------------------------- #

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:">
<title>HONEYCOMB</title>
<style>
:root{
  color-scheme:light;
  --page:#f9f9f7;--surface:#fcfcfb;--ink:#0b0b0b;--ink2:#52514e;--muted:#898781;
  --grid:#e1e0d9;--axis:#c3c2b7;--border:rgba(11,11,11,.10);--wash:rgba(11,11,11,.04);
  --s1:#2a78d6;--s2:#eb6834;--s3:#1baf7a;--s4:#eda100;--s5:#e87ba4;--s6:#008300;--s7:#6250d6;--s8:#e34948;
  --agg:#6b6a65;--good:#0ca30c;--warning:#fab219;--serious:#ec835a;--critical:#d03b3b;
}
@media (prefers-color-scheme:dark){
  :root:where(:not([data-theme="light"])){
    color-scheme:dark;
    --page:#0d0d0d;--surface:#1a1a19;--ink:#f0efec;--ink2:#c3c2b7;--muted:#898781;
    --grid:#2c2c2a;--axis:#383835;--border:rgba(255,255,255,.10);--wash:rgba(255,255,255,.05);
    --s1:#3987e5;--s2:#d95926;--s3:#199e70;--s4:#c98500;--s5:#d55181;--s6:#008300;--s7:#9085e9;--s8:#e66767;
    --agg:#a3a29a;
  }
}
:root[data-theme="dark"]{
  color-scheme:dark;
  --page:#0d0d0d;--surface:#1a1a19;--ink:#f0efec;--ink2:#c3c2b7;--muted:#898781;
  --grid:#2c2c2a;--axis:#383835;--border:rgba(255,255,255,.10);--wash:rgba(255,255,255,.05);
  --s1:#3987e5;--s2:#d95926;--s3:#199e70;--s4:#c98500;--s5:#d55181;--s6:#008300;--s7:#9085e9;--s8:#e66767;
  --agg:#a3a29a;
}
*{box-sizing:border-box}
body{margin:0;background:var(--page);color:var(--ink);font:14px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif}
header{display:flex;align-items:center;gap:16px;padding:16px 24px 0;flex-wrap:wrap}
header h1{font-size:18px;margin:0;font-weight:650}
header .meta{color:var(--muted);font-size:12px;flex:1}
button,select,input{font:inherit;color:inherit}
.btn{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:5px 10px;cursor:pointer}
.btn:hover{background:var(--wash)}
nav{display:flex;gap:4px;padding:12px 24px 0;border-bottom:1px solid var(--grid);overflow-x:auto}
nav button{background:none;border:0;border-bottom:2px solid transparent;padding:8px 12px;cursor:pointer;color:var(--ink2);display:flex;align-items:center;gap:8px;white-space:nowrap}
nav button[aria-selected="true"]{color:var(--ink);border-bottom-color:var(--ink);font-weight:600}
.sw{display:inline-block;width:10px;height:10px;border-radius:2px;flex:none}
main{padding:20px 24px 48px;max-width:1400px}
.kpis{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:12px;margin-bottom:20px}
.kpi{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:12px 14px}
.kpi .v{font-size:24px;font-weight:650;margin-top:2px}
.kpi .l{font-size:12px;color:var(--ink2)}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(420px,1fr));gap:16px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:14px 16px;min-width:0}
.card.wide{grid-column:1/-1}
.card h2{font-size:14px;margin:0 0 2px;font-weight:600}
.card .sub{font-size:12px;color:var(--muted);margin:0 0 10px}
.bars{display:grid;grid-template-columns:minmax(0,1.1fr) minmax(0,1fr) auto;gap:5px 10px;align-items:center}
.bars .lab{font:12px ui-monospace,SFMono-Regular,Consolas,monospace;color:var(--ink);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.bars .trk{height:14px;position:relative}
.bars .bar{position:absolute;left:0;top:0;bottom:0;border-radius:0 4px 4px 0;min-width:2px}
.bars .val{font-size:12px;color:var(--ink2);font-variant-numeric:tabular-nums;text-align:right}
.bars .row{display:contents}
.bars .row:hover .lab{text-decoration:underline}
.empty{color:var(--muted);font-size:13px;padding:8px 0}
table{border-collapse:collapse;width:100%;font-size:12.5px}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--grid);vertical-align:top}
th{color:var(--ink2);font-weight:600;position:sticky;top:0;background:var(--surface)}
td.n,th.n{text-align:right;font-variant-numeric:tabular-nums}
td.ip{white-space:nowrap}
td.mono{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;word-break:break-all}
.tag{display:inline-block;border:1px solid var(--border);border-radius:999px;padding:0 7px;margin:1px 2px 1px 0;font-size:11px;color:var(--ink2)}
.conf{display:inline-flex;align-items:center;gap:5px;font-size:12px}
.conf i{width:8px;height:8px;border-radius:50%;display:inline-block}
.legend{display:flex;gap:14px;flex-wrap:wrap;font-size:12px;color:var(--ink2);margin:0 0 6px}
.legend span{display:flex;align-items:center;gap:6px}
.tablewrap{max-height:560px;overflow:auto}
details summary{cursor:pointer;color:var(--ink2);font-size:12px;margin-top:8px}
.toolbar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:10px}
.toolbar input[type=search]{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:5px 10px;min-width:260px}
.toolbar select{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:5px 8px}
.seg button{border-radius:0;margin-left:-1px}
.seg button:first-child{border-radius:8px 0 0 8px}.seg button:last-child{border-radius:0 8px 8px 0}
.seg button[aria-pressed="true"]{background:var(--ink);color:var(--surface)}
#tip{position:fixed;pointer-events:none;background:var(--surface);color:var(--ink);border:1px solid var(--border);border-radius:8px;padding:8px 10px;font-size:12px;box-shadow:0 4px 16px rgba(0,0,0,.12);display:none;z-index:10;max-width:520px}
#tip .tv{font-weight:650;font-size:13px}
#tip .tr{display:flex;align-items:center;gap:8px}
#tip .tr b{font-variant-numeric:tabular-nums}
#tip .key{width:12px;height:2px;display:inline-block}
#tip .tl{color:var(--ink2);word-break:break-all}
svg text{fill:var(--muted);font-size:11px}
.note{font-size:12px;color:var(--muted)}
.flag{display:inline-block;min-width:1.45em;margin-right:6px;font-size:15px;line-height:1;text-align:center;vertical-align:-1px;font-family:"Twemoji Mozilla","Apple Color Emoji","Segoe UI Emoji","Noto Color Emoji",sans-serif}
.flag.code{font:600 9.5px/1 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;letter-spacing:.04em;padding:3px 4px;border-radius:3px;border:1px solid var(--border);background:var(--wash);color:var(--ink2);min-width:0;vertical-align:1px}
.geo{color:var(--muted);font-size:11.5px;white-space:nowrap}
.matrix{display:flex;gap:8px;overflow-x:auto;padding-bottom:4px}
.tactic{flex:1 0 104px;min-width:104px;display:flex;flex-direction:column;gap:6px}
.tactic h3{margin:0 0 2px;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.05em;color:var(--ink2);border-bottom:2px solid var(--axis);padding-bottom:4px}
.tech{display:block;position:relative;border:1px solid var(--border);border-radius:6px;padding:6px 7px 6px 9px;text-decoration:none;color:var(--ink);font-size:11.5px;line-height:1.3;overflow:hidden}
.tech:hover,.tech:focus-visible{border-color:var(--ink2);outline:none}
.tech .heat{position:absolute;inset:0;background:var(--critical);pointer-events:none}
.tech .tid{position:relative;font:600 10.5px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;color:var(--ink2)}
.tech .tn{position:relative;display:block}
.tech .tc{position:relative;float:right;font-weight:600;font-variant-numeric:tabular-nums}
.tactic .none{font-size:11px;color:var(--muted);padding:4px 0}
@media (forced-colors:active){.bar,.sw{forced-color-adjust:none}}
</style>
</head>
<body>
<header>
  <svg width="26" height="28" viewBox="0 0 26 28" aria-hidden="true"><path d="M13 1l11 6.3v13.4L13 27 2 20.7V7.3z" fill="var(--s4)"/><path d="M13 8l5.2 3v6L13 20l-5.2-3v-6z" fill="var(--page)"/></svg>
  <h1>HONEYCOMB</h1>
  <div class="meta" id="meta"></div>
  <button class="btn" id="theme" type="button">Theme</button>
</header>
<nav id="tabs" role="tablist"></nav>
<main id="view"></main>
<div id="tip" role="tooltip"></div>
<script type="application/json" id="data">__DATA__</script>
<script>
"use strict";
const D = JSON.parse(document.getElementById("data").textContent);
const SLOTS = 8;
D.sensors.forEach((s, i) => { s.color = i < SLOTS ? `var(--s${i + 1})` : "var(--agg)"; });
const SENS = Object.fromEntries(D.sensors.map(s => [s.id, s]));
const fmt = n => (n === null || n === undefined) ? "\u2013" : Number(n).toLocaleString();
const $ = (tag, attrs, ...kids) => {
  const el = document.createElement(tag);
  if (attrs) for (const [k, v] of Object.entries(attrs)) {
    if (k === "text") el.textContent = v;
    else if (k === "class") el.className = v;
    else if (k === "style") el.setAttribute("style", v);
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v);
  }
  for (const c of kids) if (c != null) el.append(c);
  return el;
};
const SVGNS = "http://www.w3.org/2000/svg";
const S = (tag, attrs) => { const el = document.createElementNS(SVGNS, tag); for (const [k, v] of Object.entries(attrs || {})) el.setAttribute(k, v); return el; };
const fdate = s => s ? s.replace("T", " ").replace("Z", " UTC") : "\u2013";

/* ---------- theme ---------- */
(function () {
  let t = null; try { t = localStorage.getItem("honeycomb-theme"); } catch (e) {}
  if (t) document.documentElement.dataset.theme = t;
  document.getElementById("theme").onclick = () => {
    const cur = document.documentElement.dataset.theme ||
      (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
    const nxt = cur === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = nxt;
    try { localStorage.setItem("honeycomb-theme", nxt); } catch (e) {}
  };
})();

/* ---------- tooltip ---------- */
const tip = document.getElementById("tip");
function showTip(ev, build) {
  tip.replaceChildren(); build(tip); tip.style.display = "block";
  const r = tip.getBoundingClientRect();
  let x = (ev.clientX ?? 0) + 14, y = (ev.clientY ?? 0) + 14;
  if (ev.type === "focus") { const b = ev.target.getBoundingClientRect(); x = b.left; y = b.bottom + 6; }
  if (x + r.width > innerWidth - 8) x = innerWidth - r.width - 8;
  if (y + r.height > innerHeight - 8) y = (ev.clientY ?? y) - r.height - 10;
  tip.style.left = x + "px"; tip.style.top = y + "px";
}
const hideTip = () => { tip.style.display = "none"; };
function hoverable(el, build) {
  el.addEventListener("pointermove", e => showTip(e, build));
  el.addEventListener("pointerleave", hideTip);
  el.addEventListener("focus", e => showTip(e, build));
  el.addEventListener("blur", hideTip);
}

/* ---------- components ---------- */
function card(title, sub, body, wide) {
  return $("section", { class: "card" + (wide ? " wide" : "") },
    $("h2", { text: title }), sub ? $("p", { class: "sub", text: sub }) : null, body);
}
function kpis(k) {
  const items = [["Events", k.events], ["Unique source IPs", k.unique_ips], ["Sessions / connections", k.sessions]];
  if (k.honeypots > 1) items.push(["Honeypot types", k.honeypots]);
  if (k.login_attempts) items.push(["Login attempts", k.login_attempts], ["Successful logins", k.login_success]);
  if (k.commands) items.push(["Commands run", k.commands]);
  if (k.unique_hashes) items.push(["Unique payload hashes", k.unique_hashes]);
  if (k.unique_urls) items.push(["Unique URLs", k.unique_urls]);
  if (k.requests) items.push(["Requests", k.requests]);
  items.push(["Services hit", k.protocols]);
  if (k.avg_session_s !== null) items.push(["Avg session (s)", k.avg_session_s]);
  return $("div", { class: "kpis" }, ...items.map(([l, v]) => $("div", { class: "kpi" }, $("div", { class: "l", text: l }), $("div", { class: "v", text: fmt(v) }))));
}
// Flag emoji are two "regional indicator" letters. Windows has no flag glyphs and would show
// the bare letters, so test once on a canvas and fall back to a neat country-code badge.
const FLAGS_OK = (() => { try {
  const c = document.createElement("canvas"); c.width = c.height = 20; const x = c.getContext("2d");
  x.textBaseline = "top"; x.font = '16px "Apple Color Emoji","Segoe UI Emoji","Noto Color Emoji",sans-serif';
  x.fillText("\u{1F1FA}\u{1F1F8}", 0, 0); const d = x.getImageData(0, 0, 20, 20).data;
  for (let i = 0; i < d.length; i += 4) if (d[i + 3] && (Math.abs(d[i] - d[i + 1]) > 20 || Math.abs(d[i + 1] - d[i + 2]) > 20)) return true;
  return false; } catch (e) { return false; } })();
const REGION = (() => { try { return new Intl.DisplayNames(["en"], { type: "region" }); } catch (e) { return null; } })();
function ccName(cc) { try { return (REGION && REGION.of(cc)) || cc; } catch (e) { return cc; } }
function flagEl(cc) {
  if (!cc || !/^[A-Z]{2}$/.test(cc)) return $("span", { class: "flag code", text: "??", title: "Unknown location" });
  if (!FLAGS_OK) return $("span", { class: "flag code", text: cc, title: ccName(cc) });
  return $("span", { class: "flag", text: String.fromCodePoint(...[...cc].map(ch => 0x1F1E6 + ch.charCodeAt(0) - 65)), title: ccName(cc), role: "img", "aria-label": ccName(cc) });
}
const GEO = D.geo || {};
function ipDeco(ip) { const g = GEO[ip]; return g && g[0] ? flagEl(g[0]) : null; }
function geoText(ip) { const g = GEO[ip]; if (!g) return ""; return [g[3], g[0] ? ccName(g[0]) : "", g[1] ? `AS${g[1]} ${g[2]}` : ""].filter(Boolean).join(" \u00b7 "); }
function countryList(rows, color) {
  return barList(rows.map(r => [r[0], r[1]]), color, "events", cc => flagEl(cc), cc => `${ccName(cc)}`,
    rows.reduce((m, r) => (m[r[0]] = ` \u00b7 ${fmt(r[2])} IP${r[2] === 1 ? "" : "s"}`, m), {}));
}
function attackMatrix(rows) {
  if (!rows || !rows.length) return $("div", { class: "empty", text: "No techniques observed" });
  const ref = D.attack_ref, max = Math.max(...rows.map(r => r[1])), by = {};
  rows.forEach(([t, n]) => { const tac = (ref[t] || ["", "other"])[1]; (by[tac] = by[tac] || []).push([t, n]); });
  const m = $("div", { class: "matrix" });
  D.tactics.forEach(tac => {
    const col = $("div", { class: "tactic" }, $("h3", { text: tac.replace(/-/g, " ").replace("command and control", "C2") }));
    (by[tac] || []).forEach(([t, n]) => {
      const a = $("a", { class: "tech", href: "https://attack.mitre.org/techniques/" + t.replace(".", "/") + "/", target: "_blank", rel: "noopener noreferrer" },
        $("span", { class: "heat", style: `opacity:${(0.07 + 0.33 * n / max).toFixed(2)}` }),
        $("span", { class: "tc", text: fmt(n) }), $("span", { class: "tid", text: t }),
        $("span", { class: "tn", text: (ref[t] || [t])[0].replace(/^[^:]+: /, "") }));
      col.append(a);
      hoverable(a, tt => { tt.append($("div", { class: "tv", text: `${fmt(n)} attacker IP${n === 1 ? "" : "s"}` }), $("div", { class: "tl", text: `${t} ${(ref[t] || [""])[0]}` })); });
    });
    if (!by[tac]) col.append($("div", { class: "none", text: "\u2013" }));
    m.append(col);
  });
  return $("div", null, m, $("p", { class: "sub", style: "margin:8px 0 0", text: "Attacker IPs per technique, from commands, logins, downloads, exploits and scans. Click a technique for the MITRE ATT&CK page." }));
}
function barList(rows, color, unit, deco, labelFn, suffix) {
  if (!rows || !rows.length) return $("div", { class: "empty", text: "No data" });
  const max = Math.max(...rows.map(r => r[1]));
  const wrap = $("div", { class: "bars" });
  rows.forEach(([label, v]) => {
    const bar = $("div", { class: "bar", style: `width:${Math.max(0.5, v / max * 100)}%;background:${color}` });
    const row = $("div", { class: "row", tabindex: "0" },
      $("div", { class: "lab" }, deco ? deco(label) : null,
        document.createTextNode((label === "" ? "(empty)" : labelFn ? labelFn(label) : label) + (suffix && suffix[label] ? suffix[label] : ""))),
      $("div", { class: "trk" }, bar),
      $("div", { class: "val", text: fmt(v) }));
    wrap.append(row);
    [...row.children].forEach(c => hoverable(c, t => {
      t.append($("div", { class: "tv", text: fmt(v) + " " + (unit || "") }), $("div", { class: "tl", text: label === "" ? "(empty)" : labelFn ? labelFn(label) : label }));
      if (deco && GEO[label]) t.append($("div", { class: "tl", text: geoText(label) }));
    }));
  });
  return wrap;
}
function legend(sensors) {
  return $("div", { class: "legend" }, ...sensors.map(s => $("span", null, $("i", { class: "sw", style: `background:${s.color}` }), document.createTextNode(s.label))));
}

/* ---------- timeline (stacked columns) ---------- */
function bucketize(seriesMap) {
  const all = new Set();
  Object.values(seriesMap).forEach(arr => arr.forEach(([h]) => all.add(h)));
  if (!all.size) return null;
  const hrs = [...all].sort();
  const t0 = Date.parse(hrs[0] + ":00:00Z"), t1 = Date.parse(hrs[hrs.length - 1] + ":00:00Z");
  const spanH = (t1 - t0) / 3600e3;
  const daily = spanH > 168;
  const step = daily ? 86400e3 : 3600e3;
  const start = daily ? Date.parse(hrs[0].slice(0, 10) + "T00:00:00Z") : t0;
  const n = Math.floor((t1 - start) / step) + 1;
  const keys = [];
  for (let i = 0; i < n; i++) keys.push(new Date(start + i * step).toISOString().slice(0, daily ? 10 : 13));
  const idx = Object.fromEntries(keys.map((k, i) => [k, i]));
  const out = {};
  for (const [id, arr] of Object.entries(seriesMap)) {
    const v = new Array(n).fill(0);
    arr.forEach(([h, c]) => { v[idx[daily ? h.slice(0, 10) : h]] += c; });
    out[id] = v;
  }
  return { keys, daily, values: out };
}
function niceMax(m) {
  if (m <= 0) return 1;
  const p = Math.pow(10, Math.floor(Math.log10(m))), f = m / p;
  return (f <= 1 ? 1 : f <= 2 ? 2 : f <= 2.5 ? 2.5 : f <= 5 ? 5 : 10) * p;
}
const tickFmt = v => v >= 10000 ? (v / 1000).toLocaleString() + "K" : v.toLocaleString();
function roundTop(x, y, w, h, r) {
  r = Math.min(r, w / 2, h);
  return `M${x},${y + h}V${y + r}Q${x},${y} ${x + r},${y}H${x + w - r}Q${x + w},${y} ${x + w},${y + r}V${y + h}Z`;
}
function timeline(seriesMap, ids) {
  const B = bucketize(seriesMap);
  if (!B) return $("div", { class: "empty", text: "No timestamped events" });
  const W = 1000, H = 240, L = 48, R = 8, T = 10, Bm = 26;
  const pw = W - L - R, ph = H - T - Bm, n = B.keys.length;
  const totals = B.keys.map((_, i) => ids.reduce((a, id) => a + (B.values[id] ? B.values[id][i] : 0), 0));
  const ymax = niceMax(Math.max(...totals));
  const svg = S("svg", { viewBox: `0 0 ${W} ${H}`, width: "100%", role: "img", "aria-label": "Events over time" });
  for (let t = 0; t <= 4; t++) {
    const v = ymax * t / 4, y = T + ph - ph * t / 4;
    svg.append(S("line", { x1: L, x2: W - R, y1: y, y2: y, stroke: t ? "var(--grid)" : "var(--axis)", "stroke-width": 1 }));
    const tx = S("text", { x: L - 6, y: y + 4, "text-anchor": "end" }); tx.textContent = tickFmt(Math.round(v)); svg.append(tx);
  }
  const slot = pw / n, gap = slot > 6 ? 2 : 0, bw = Math.min(24, Math.max(1, slot - gap));
  const lblEvery = Math.max(1, Math.ceil(n / 8));
  B.keys.forEach((k, i) => {
    const x = L + i * slot + (slot - bw) / 2;
    let y = T + ph;
    const segs = ids.filter(id => B.values[id] && B.values[id][i] > 0);
    segs.forEach((id, j) => {
      const h = B.values[id][i] / ymax * ph;
      const gh = (j > 0 && h > 3) ? 2 : 0;
      y -= h;
      const top = j === segs.length - 1;
      const el = top ? S("path", { d: roundTop(x, y, bw, Math.max(0, h - gh), bw >= 8 ? 4 : 1), fill: SENS[id] ? SENS[id].color : "var(--agg)" })
                     : S("rect", { x, y, width: bw, height: Math.max(0, h - gh), fill: SENS[id] ? SENS[id].color : "var(--agg)" });
      if (!SENS[id]) el.setAttribute("fill", "var(--agg)");
      svg.append(el);
    });
    if (i % lblEvery === 0) {
      const tx = S("text", { x: L + i * slot + slot / 2, y: H - 8, "text-anchor": "middle" });
      tx.textContent = B.daily ? k.slice(5) : k.slice(5, 10) + " " + k.slice(11) + "h"; svg.append(tx);
    }
    const hit = S("rect", { x: L + i * slot, y: T, width: slot, height: ph, fill: "transparent", tabindex: "0" });
    hoverable(hit, t => {
      t.append($("div", { class: "tv", text: fmt(totals[i]) + " events" }), $("div", { class: "tl", text: B.daily ? k : k.replace("T", " ") + ":00 UTC" }));
      if (ids.length > 1) ids.forEach(id => t.append($("div", { class: "tr" }, $("i", { class: "key", style: `background:${SENS[id].color}` }), $("b", { text: fmt(B.values[id] ? B.values[id][i] : 0) }), $("span", { class: "tl", text: SENS[id].label }))));
    });
    svg.append(hit);
  });
  const wrap = $("div");
  if (ids.length > 1) wrap.append(legend(ids.map(id => SENS[id])));
  wrap.append(svg);
  const tbl = $("table", null, $("tr", null, $("th", { text: B.daily ? "Day (UTC)" : "Hour (UTC)" }), ...ids.map(id => $("th", { class: "n", text: SENS[id] ? SENS[id].label : id })), ids.length > 1 ? $("th", { class: "n", text: "Total" }) : null));
  B.keys.forEach((k, i) => { if (totals[i]) tbl.append($("tr", null, $("td", { text: k.replace("T", " ") }), ...ids.map(id => $("td", { class: "n", text: fmt(B.values[id] ? B.values[id][i] : 0) })), ids.length > 1 ? $("td", { class: "n", text: fmt(totals[i]) }) : null)); });
  wrap.append($("details", null, $("summary", { text: "Show as table" }), $("div", { class: "tablewrap" }, tbl)));
  return wrap;
}

/* ---------- views ---------- */
function tagEls(tags) { return (tags || []).map(t => $("span", { class: "tag", text: t })); }
const CONFC = { high: "var(--critical)", medium: "var(--serious)", low: "var(--muted)" };

function viewOverview() {
  const o = D.overview;
  const v = $("div");
  v.append(kpis(o.kpi));
  const g = $("div", { class: "grid" });
  g.append(card("Events over time", "All sensors, stacked by sensor (UTC)", timeline(D.series, D.sensors.map(s => s.id)), true));
  const dash = (n, x) => n ? x : "\u2013";
  const cmp = $("table", null, $("tr", null, ...["Sensor", "Honeypots", "Events", "Unique IPs", "Sessions", "Logins (ok)", "Commands", "Payloads", "First seen", "Last seen"].map((h, i) => $("th", { class: i > 1 && i < 8 ? "n" : "", text: h }))));
  D.sensors.forEach(s => { const k = s.stats.kpi; cmp.append($("tr", null,
    $("td", null, $("span", { style: "display:flex;gap:8px;align-items:center" }, $("i", { class: "sw", style: `background:${s.color}` }), document.createTextNode(s.label))),
    $("td", { text: s.kinds.join(", ") }), $("td", { class: "n", text: fmt(k.events) }), $("td", { class: "n", text: fmt(k.unique_ips) }),
    $("td", { class: "n", text: fmt(k.sessions) }), $("td", { class: "n", text: dash(k.login_attempts, `${fmt(k.login_attempts)} (${fmt(k.login_success)})`) }),
    $("td", { class: "n", text: dash(k.commands, fmt(k.commands)) }), $("td", { class: "n", text: dash(k.unique_hashes, fmt(k.unique_hashes)) }),
    $("td", { text: fdate(s.stats.first) }), $("td", { text: fdate(s.stats.last) }))); });
  g.append(card("Sensors side by side", null, $("div", { class: "tablewrap" }, cmp), true));
  const cross = $("table", null, $("tr", null, ...["Source IP", "Sensors", "Events", "First seen", "Last seen", "Tags"].map((h, i) => $("th", { class: i === 2 ? "n" : "", text: h }))));
  D.cross.slice(0, 200).forEach(c => cross.append($("tr", null, $("td", { class: "mono ip", title: geoText(c.ip) }, ipDeco(c.ip), document.createTextNode(c.ip)),
    $("td", null, ...c.sensors.map(id => $("span", { class: "tag" }, $("i", { class: "sw", style: `background:${SENS[id].color};width:8px;height:8px;margin-right:4px` }), document.createTextNode(SENS[id].label)))),
    $("td", { class: "n", text: fmt(c.events) }), $("td", { text: fdate(c.first) }), $("td", { text: fdate(c.last) }), $("td", null, ...tagEls(c.tags)))));
  g.append(card(`IPs hitting more than one sensor (${fmt(D.cross_total)})`, "Actors spraying your whole footprint - usually the best IOCs to share",
    D.cross.length ? $("div", { class: "tablewrap" }, cross) : $("div", { class: "empty", text: "No overlap yet" }), true));
  g.append(card("MITRE ATT&CK", "Techniques observed across all sensors", attackMatrix(o.attack), true));
  if (o.countries.length) g.append(card("Top countries", `Events by attacker location (unique IPs alongside) \u00b7 Geo: ${D.meta.geo_source || "n/a"}`, countryList(o.countries, "var(--agg)")));
  if (o.asns.length) g.append(card("Top networks", "Events by autonomous system", barList(o.asns, "var(--agg)", "events")));
  g.append(card("Top source IPs", "All sensors", barList(o.top_ips, "var(--agg)", "events", ipDeco)));
  if (o.honeypots.length > 1) g.append(card("Honeypots", "Events by honeypot type, all sensors", barList(o.honeypots, "var(--agg)", "events")));
  if (o.combos.length) g.append(card("Top username / password pairs", "All sensors", barList(o.combos, "var(--agg)", "attempts")));
  if (o.cmd_cats.length) g.append(card("Command behaviour", "Commands matching each category (one command can match several)", barList(o.cmd_cats, "var(--agg)", "commands")));
  if (o.commands.length) g.append(card("Top commands", "All sensors", barList(o.commands, "var(--agg)", "runs")));
  g.append(card("Services", "Sessions/connections by protocol or service", barList(o.protocols, "var(--agg)", "sessions")));
  if (o.requests.length) g.append(card("Top requests", "Service: request (HTTP lines, SMTP verbs, SIP methods, ICS/HL7 messages...)", barList(o.requests, "var(--agg)", "times"), true));
  if (o.urls.length) g.append(card("URLs seen", "Downloads, URLs in commands and in payloads", barList(o.urls, "var(--agg)", "times")));
  v.append(g);
  return v;
}

function viewSensor(s) {
  const st = s.stats, c = s.color, v = $("div");
  v.append($("p", { class: "note", text: [s.location, s.kinds.join(" + "), `exported as "${s.export_name}"`, st.first ? `${fdate(st.first)} \u2192 ${fdate(st.last)}` : ""].filter(Boolean).join(" \u00b7 ") }));
  if (s.skipped && s.skipped.length) v.append($("p", { class: "note", text: `Skipped ${s.skipped.length} conpot.log file(s) because conpot.json exists (use --conpot-text-too to include).` }));
  v.append(kpis(st.kpi));
  const g = $("div", { class: "grid" });
  const add = (rows, ...args) => { if (rows && rows.length) g.append(card(...args)); };
  g.append(card("Events over time", "UTC", timeline({ [s.id]: D.series[s.id] || [] }, [s.id]), true));
  if (st.honeypots.length > 1) g.append(card("Honeypots on this sensor", null, barList(st.honeypots, c, "events")));
  g.append(card("MITRE ATT&CK", "Techniques observed on this sensor", attackMatrix(st.attack), true));
  add(st.countries, "Top countries", `Events by attacker location \u00b7 Geo: ${D.meta.geo_source || "n/a"}`, countryList(st.countries, c));
  add(st.asns, "Top networks", "Events by autonomous system", barList(st.asns, c, "events"));
  g.append(card("Top source IPs", null, barList(st.top_ips, c, "events", ipDeco)));
  add(st.usernames, "Top usernames", null, barList(st.usernames, c, "attempts"));
  add(st.passwords, "Top passwords", null, barList(st.passwords, c, "attempts"));
  add(st.combos, "Top username / password pairs", null, barList(st.combos, c, "attempts"));
  add(st.ok_combos, "Credentials that got in", "Successful logins", barList(st.ok_combos, c, "logins"));
  add(st.cmd_cats, "Command behaviour", "Commands matching each category", barList(st.cmd_cats, c, "commands"));
  add(st.commands, "Top commands", null, barList(st.commands, c, "runs"), true);
  add(st.requests, "Top requests", "Service: request", barList(st.requests, c, "times"), true);
  add(st.urls, "URLs", "Downloads, URLs in commands and in payloads", barList(st.urls, c, "times"));
  add(st.hashes, "Payload SHA-256", "Downloaded / uploaded / captured files", barList(st.hashes, c, "times"));
  add(st.clients, "Clients / user agents", "SSH client versions, HTTP and SIP user agents", barList(st.clients, c, "sessions"));
  add(st.hassh, "HASSH fingerprints", null, barList(st.hassh, c, "sessions"));
  add(st.sshkeys, "SSH keys tried", "Public keys attackers offered for login (SHA256 fingerprint)", barList(st.sshkeys, c, "attempts"));
  add(st.tunnels, "Tunnel (direct-tcpip) targets", "Attackers trying to proxy through the honeypot", barList(st.tunnels, c, "requests"));
  g.append(card("Services", "Sessions/connections by protocol or service", barList(st.protocols, c, "sessions")));
  g.append(card("Destination ports", null, barList(st.ports, c, "sessions")));
  g.append(card("Event types", null, barList(st.eventtypes, c, "events")));
  v.append(g);
  return v;
}

function viewIOCs() {
  const v = $("div");
  const types = ["all", ...new Set(D.iocs.map(i => i.type))];
  const state = { type: "all", q: "", conf: "low", multi: false };
  const counts = $("span", { class: "note" });
  const tbody = $("tbody");
  const ord = ["low", "medium", "high"];
  const filtered = () => D.iocs.filter(i => (state.type === "all" || i.type === state.type) &&
    ord.indexOf(i.confidence) >= ord.indexOf(state.conf) && (!state.multi || i.sensor_count > 1) &&
    (!state.q || [i.value, i.tags.join(" "), i.sensors.join(" "), (i.attack || []).join(" "), i.country || "",
      i.country ? ccName(i.country) : "", i.asn ? "AS" + i.asn : "", i.as_org || ""].join(" ").toLowerCase().includes(state.q)));
  function render() {
    const rows = filtered();
    counts.textContent = `${fmt(rows.length)} of ${fmt(D.iocs.length)} IOCs` + (rows.length > 1000 ? " (showing first 1,000)" : "");
    tbody.replaceChildren(...rows.slice(0, 1000).map(i => $("tr", null,
      $("td", { text: i.type }), $("td", { class: "mono", text: i.value }),
      $("td", { class: "geo", title: [i.country ? ccName(i.country) : "", i.as_org].filter(Boolean).join(" \u00b7 ") },
        i.country ? flagEl(i.country) : null, document.createTextNode([i.country, i.asn ? "AS" + i.asn : ""].filter(Boolean).join(" "))),
      $("td", null, $("span", { class: "conf" }, $("i", { style: `background:${CONFC[i.confidence]}` }), document.createTextNode(i.confidence))),
      $("td", { class: "n", text: fmt(i.count) }), $("td", { class: "n", text: i.sensor_count }),
      $("td", { text: fdate(i.first_seen) }), $("td", { text: fdate(i.last_seen) }),
      $("td", null, ...tagEls(i.tags)),
      $("td", null, ...(i.attack || []).map(t => $("a", { class: "tag mono", href: "https://attack.mitre.org/techniques/" + t.replace(".", "/") + "/", target: "_blank", rel: "noopener noreferrer", text: t, title: (D.attack_ref[t] || [t])[0] }))),
      $("td", { class: "note", text: i.context }))));
  }
  const seg = $("div", { class: "seg" }, ...types.map(t => { const b = $("button", { class: "btn", type: "button", "aria-pressed": String(t === "all"), text: t }); b.onclick = () => { state.type = t; seg.querySelectorAll("button").forEach(x => x.setAttribute("aria-pressed", String(x === b))); render(); }; return b; }));
  const q = $("input", { type: "search", placeholder: "Search value, tag, sensor, country, ASN or T-number\u2026" }); q.oninput = () => { state.q = q.value.trim().toLowerCase(); render(); };
  const conf = $("select", null, ...["low", "medium", "high"].map(c => $("option", { value: c, text: `\u2265 ${c} confidence` }))); conf.onchange = () => { state.conf = conf.value; render(); };
  const multi = $("label", { class: "note", style: "display:flex;gap:6px;align-items:center" }, $("input", { type: "checkbox", onchange: e => { state.multi = e.target.checked; render(); } }), document.createTextNode("multi-sensor only"));
  const copy = $("button", { class: "btn", type: "button", text: "Copy values" });
  copy.onclick = () => { const txt = filtered().map(i => i.value).join("\n"); const done = () => { copy.textContent = "Copied"; setTimeout(() => copy.textContent = "Copy values", 1200); };
    if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(txt).then(done, () => fallback(txt, done)); else fallback(txt, done); };
  function fallback(txt, done) { const ta = $("textarea"); ta.value = txt; document.body.append(ta); ta.select(); try { document.execCommand("copy"); done(); } catch (e) {} ta.remove(); }
  const dl = $("button", { class: "btn", type: "button", text: "Download CSV" });
  dl.onclick = () => { const esc = s => { s = String(s ?? ""); if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; return '"' + s.replace(/"/g, '""') + '"'; };
    const rows = [["type", "value", "confidence", "count", "sensor_count", "sensors", "first_seen", "last_seen", "tags", "attack", "country", "asn", "as_org", "context"]].concat(filtered().map(i => [i.type, i.value, i.confidence, i.count, i.sensor_count, i.sensors.join(";"), i.first_seen, i.last_seen, i.tags.join(";"), (i.attack || []).join(";"), i.country || "", i.asn || "", i.as_org || "", i.context]));
    const a = $("a", { href: URL.createObjectURL(new Blob([rows.map(r => r.map(esc).join(",")).join("\r\n")], { type: "text/csv" })), download: "honeycomb_iocs_filtered.csv" }); document.body.append(a); a.click(); a.remove(); };
  const where = D.meta.out ? `were written to ${D.meta.out}${D.meta.out.includes("\\") ? "\\" : "/"}iocs` : "are in the iocs folder";
  v.append($("p", { class: "note", text: D.meta.public
    ? `Public view: only shareable IOCs (\u2265 ${D.meta.min_confidence} confidence, TLP:${D.meta.tlp.toUpperCase()}) are shown; sensor IPs are redacted.`
    : `Shareable exports (\u2265 ${D.meta.min_confidence} confidence, TLP:${D.meta.tlp.toUpperCase()}) ${where}. IOCs tagged own-sensor, private-host or allowlisted (and shared-hosting domains) stay in this dashboard only.` }));
  v.append($("div", { class: "toolbar" }, seg, q, conf, multi, copy, dl, counts));
  const table = $("table", null, $("thead", null, $("tr", null, ...["Type", "Value", "Geo", "Confidence", "Count", "Sensors", "First seen", "Last seen", "Tags", "ATT&CK", "Context"].map((h, i) => $("th", { class: i === 4 || i === 5 ? "n" : "", text: h })))), tbody);
  v.append($("section", { class: "card wide" }, $("div", { class: "tablewrap", style: "max-height:70vh" }, table)));
  const files = $("table", null, $("tr", null, $("th", { text: "Sensor" }), $("th", { text: "Kind" }), $("th", { class: "n", text: "Lines" }), $("th", { text: "File" })));
  D.meta.files.forEach(f => files.append($("tr", null, $("td", { text: SENS[f.sensor] ? SENS[f.sensor].label : f.sensor }), $("td", { text: f.kind }), $("td", { class: "n", text: fmt(f.lines) }), $("td", { class: "mono", text: f.file }))));
  v.append($("details", { style: "margin-top:16px" }, $("summary", { text: `Files parsed (${D.meta.files.length}) \u00b7 ignored: ${fmt(D.meta.excluded_events)} excluded/private-IP events, ${fmt(D.meta.out_of_range)} out of range, ${fmt(D.meta.duplicate_lines)} duplicate lines, ${fmt(D.meta.bad_lines)} bad lines` }), $("div", { class: "card wide", style: "margin-top:8px" }, files)));
  render();
  return v;
}

/* ---------- tabs ---------- */
const tabs = [{ id: "overview", label: "Overview", render: viewOverview }]
  .concat(D.sensors.map(s => ({ id: "s:" + s.id, label: s.label, color: s.color, render: () => viewSensor(s) })))
  .concat([{ id: "iocs", label: `IOCs (${D.iocs.length.toLocaleString()})`, render: viewIOCs }]);
const nav = document.getElementById("tabs"), view = document.getElementById("view");
function go(id) {
  const t = tabs.find(x => x.id === id) || tabs[0];
  nav.querySelectorAll("button").forEach(b => b.setAttribute("aria-selected", String(b.dataset.id === t.id)));
  hideTip(); view.replaceChildren(t.render());
  try { history.replaceState(null, "", "#" + encodeURIComponent(t.id)); } catch (e) {}
}
tabs.forEach(t => { const b = $("button", { role: "tab", type: "button" }, t.color ? $("i", { class: "sw", style: `background:${t.color}` }) : null, document.createTextNode(t.label)); b.dataset.id = t.id; b.onclick = () => go(t.id); nav.append(b); });
document.getElementById("meta").textContent = `${D.sensors.length} sensors \u00b7 ${fmt(D.overview.kpi.events)} events \u00b7 ${fdate(D.overview.first)} \u2192 ${fdate(D.overview.last)} \u00b7 generated ${fdate(D.meta.generated)}`;
go(decodeURIComponent(location.hash.slice(1)) || "overview");
addEventListener("hashchange", () => { const id = decodeURIComponent(location.hash.slice(1)); if (!nav.querySelector(`button[aria-selected="true"]`) || nav.querySelector(`button[aria-selected="true"]`).dataset.id !== id) go(id); });
</script>
</body>
</html>
"""

if __name__ == "__main__":
    sys.exit(main())