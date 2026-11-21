"""Pure-function tests: parse, normalize, validate, identity, pipeline. No files, no database.
Run: python3 -m unittest discover -s tests   (from the log-ingestion folder)
"""

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from logingest.identity import event_id  # noqa: E402
from logingest.normalize import normalize, us_to_iso  # noqa: E402
from logingest.parse import ParseError, parse_line, raw_sha256  # noqa: E402
from logingest.pipeline import process_line  # noqa: E402
from logingest.reader import Line  # noqa: E402
from logingest.validate import validate  # noqa: E402

FIX = Path(__file__).resolve().parent / "fixtures"

HTTP = (b'{"ts":1795115970.014435,"uid":"CoY6kG2XgAjIVXJa39","id.orig_h":"10.10.10.127","id.orig_p":38180,'
        b'"id.resp_h":"10.10.20.20","id.resp_p":80,"proto":"tcp","service":"http","duration":0.0038788318634033203,'
        b'"orig_bytes":93,"resp_bytes":431,"conn_state":"SF","local_orig":true,"local_resp":true,"missed_bytes":0,'
        b'"history":"ShADadFf","orig_pkts":7,"orig_ip_bytes":465,"resp_pkts":5,"resp_ip_bytes":699}')

SOFTWARE = (b'{"ts":1795115970.014435,"host":"10.10.35.10","host_p":22,'
            b'"software_type":"SERVER","name":"OpenSSH",'
            b'"version":{"major":9,"minor":9,"addl":"p1"},'
            b'"unparsed_version":"OpenSSH_9.9p1 Alpine"}')
NGINX_FLATTENED_SOFTWARE = (b'{"ts":1795282795.723652,"host":"10.10.20.20",'
                             b'"host_p":80,"software_type":"HTTP::SERVER",'
                             b'"name":"nginx","version.major":1,"version.minor":30,'
                             b'"version.minor2":7,"unparsed_version":"nginx/1.30.7"}')
OPENSSH_FLATTENED_SOFTWARE = (b'{"ts":1795282796.37302,"host":"10.10.35.10",'
                               b'"host_p":22,"software_type":"SSH::SERVER",'
                               b'"name":"OpenSSH","version.major":9,"version.minor":9,'
                               b'"unparsed_version":"OpenSSH_9.9"}')


def conn(**over):
    rec = json.loads(HTTP)
    for k, v in over.items():
        k = k.replace("__", ".")
        if v is ...:
            rec.pop(k, None)
        else:
            rec[k] = v
    return json.dumps(rec).encode()


def run(raw, log_type="conn", probe="probe1"):
    return process_line(probe, log_type, f"{probe}:{log_type}", "/x.log", Line(raw, 0, len(raw)), "T")


class Parse(unittest.TestCase):
    def test_codes(self):
        cases = {
            b'{"a":1,"a":2}': "duplicate_key",
            b'{"a":NaN}': "non_finite_number",
            b'{"a":Infinity}': "non_finite_number",
            b'[1,2]': "not_object",
            b'{"a":': "invalid_json",
            b'\xff\xfe{}': "invalid_utf8",
        }
        for raw, code in cases.items():
            with self.assertRaises(ParseError, msg=raw) as cm:
                parse_line(raw)
            self.assertEqual(cm.exception.code, code)

    def test_timestamp_keeps_all_digits(self):
        n = normalize("conn", parse_line(HTTP))
        self.assertEqual(n.observed_at_us, 1795115970014435)
        self.assertEqual(us_to_iso(n.observed_at_us), "2026-11-19T19:19:30.014435Z")


class NormalizeConn(unittest.TestCase):
    def test_http_flow(self):
        n = normalize("conn", parse_line(HTTP))
        self.assertIsNone(validate("conn", n))
        d = n.data
        self.assertEqual((d["src_ip"], d["src_port"], d["dst_ip"], d["dst_port"], d["transport"]),
                         ("10.10.10.127", 38180, "10.10.20.20", 80, "tcp"))
        self.assertEqual(d["service_hints"], ["http"])
        self.assertEqual(n.flags, [])

    def test_icmp_ports_become_type_code(self):
        n = normalize("conn", parse_line(conn(proto="icmp", id__orig_p=133, id__resp_p=134,
                                               id__orig_h="fe80::A8C1:abff:fe9f:dc7e", id__resp_h="ff02::2")))
        self.assertIsNone(validate("conn", n))
        self.assertEqual((n.data["icmp_type"], n.data["icmp_code"]), (133, 134))
        self.assertIsNone(n.data["src_port"])
        self.assertEqual(n.data["src_ip"], "fe80::a8c1:abff:fe9f:dc7e")  # canonical lower-case
        self.assertIn("icmp_pseudo_ports", n.flags)
        self.assertIn("src_link_local", n.flags)
        self.assertIn("dst_multicast", n.flags)

    def test_noise_is_flagged_not_dropped(self):
        n = normalize("conn", parse_line(conn(id__orig_h="0.0.0.0", id__resp_h="255.255.255.255",
                                               conn_state="S0")))
        self.assertIsNone(validate("conn", n))
        self.assertEqual(n.flags, ["dst_limited_broadcast", "no_reply", "src_unspecified"])
        n = normalize("conn", parse_line(conn(id__resp_h="224.0.0.251")))
        self.assertIn("mdns", n.flags)
        self.assertIn("dst_multicast", n.flags)

    def test_partial_and_missed(self):
        n = normalize("conn", parse_line(conn(conn_state="OTH", missed_bytes=10)))
        self.assertIn("partial", n.flags)
        self.assertIn("missed_bytes", n.flags)
        n = normalize("conn", parse_line(conn(history="^dA")))
        self.assertIn("partial", n.flags)

    def test_optional_fields_may_be_missing(self):
        n = normalize("conn", parse_line(conn(service=..., duration=..., orig_bytes=..., resp_bytes=...)))
        self.assertIsNone(validate("conn", n))
        self.assertEqual(n.data["service_hints"], [])
        self.assertIsNone(n.data["duration_seconds"])

    def test_bad_optional_counter_is_nulled_and_flagged(self):
        n = normalize("conn", parse_line(conn(orig_bytes=True, resp_pkts=-1)))
        self.assertIsNone(validate("conn", n))
        self.assertIsNone(n.data["orig_bytes"])
        self.assertIn("invalid_optional:orig_bytes", n.flags)
        self.assertIn("invalid_optional:resp_pkts", n.flags)

    def test_required_problems_reject(self):
        cases = [
            (conn(uid=...), "missing_field", "uid"),
            (conn(id__orig_h="10.0.0.999"), "invalid_field", "id.orig_h"),
            (conn(id__resp_p=70000), "invalid_field", "id.resp_p"),
            (conn(id__resp_p=True), "invalid_field", "id.resp_p"),
            (conn(proto="sctp"), "invalid_field", "proto"),
            (conn(ts="yesterday"), "invalid_field", "ts"),
            (conn(proto="icmp", id__orig_p=300), "invalid_field", "id.orig_p"),
        ]
        for raw, code, fld in cases:
            kind, row = run(raw)
            self.assertEqual(kind, "rejection", raw)
            self.assertEqual(row["error_code"], code, raw)
            self.assertIn(fld, json.loads(row["error_details_json"]))

    def test_port_zero_is_valid(self):
        self.assertEqual(run(conn(id__orig_p=0))[0], "observation")


class NormalizeDhcp(unittest.TestCase):
    def test_full_exchange(self):
        raw = (FIX / "probe1" / "dhcp.log").read_bytes().splitlines()[2]
        n = normalize("dhcp", parse_line(raw))
        self.assertIsNone(validate("dhcp", n))
        d = n.data
        self.assertEqual(d["assigned_ip"], "10.10.40.136")
        self.assertEqual(d["client_mac"], "aa:c1:ab:ed:2b:10")
        self.assertEqual(d["source_uids"], sorted(d["source_uids"]))
        self.assertEqual(d["message_types"], ["DISCOVER", "OFFER", "REQUEST", "ACK"])
        self.assertIsNone(d["hostname"])

    def test_no_ack_keeps_assigned_null(self):
        raw = (FIX / "probe1" / "dhcp.log").read_bytes().splitlines()[0]
        n = normalize("dhcp", parse_line(raw))
        self.assertIsNone(validate("dhcp", n))
        self.assertIsNone(n.data["assigned_ip"])  # never copied from requested_ip
        self.assertEqual(n.data["requested_ip"], "10.10.20.136")
        self.assertIn("no_assigned_ip", n.flags)

    def test_rejects(self):
        base = json.loads((FIX / "probe1" / "dhcp.log").read_bytes().splitlines()[2])
        for key, val, code in (("mac", "zz:11", "invalid_field"), ("uids", [], "invalid_field"),
                               ("msg_types", None, "missing_field"), ("assigned_addr", "nope", "invalid_field")):
            rec = dict(base, **{key: val})
            kind, row = run(json.dumps(rec).encode(), "dhcp")
            self.assertEqual((kind, row.get("error_code")), ("rejection", code), key)


class NormalizeSoftware(unittest.TestCase):
    def test_server_with_structured_version(self):
        n = normalize("software", parse_line(SOFTWARE))
        self.assertIsNone(validate("software", n))
        self.assertEqual(n.event_type, "software_observation")
        self.assertEqual(n.data["host_ip"], "10.10.35.10")
        self.assertEqual(n.data["host_port"], 22)
        self.assertEqual(n.data["software_name"], "OpenSSH")
        self.assertEqual(n.data["version"], {"major": 9, "minor": 9, "addl": "p1"})
        self.assertEqual(n.data["unparsed_version"], "OpenSSH_9.9p1 Alpine")

    def test_actual_nginx_record_preserves_flattened_version(self):
        n = normalize("software", parse_line(NGINX_FLATTENED_SOFTWARE))
        self.assertIsNone(validate("software", n))
        self.assertEqual(n.data["version"], {"major": 1, "minor": 30, "minor2": 7})
        self.assertEqual(n.data["unparsed_version"], "nginx/1.30.7")

    def test_actual_openssh_record_preserves_flattened_version(self):
        n = normalize("software", parse_line(OPENSSH_FLATTENED_SOFTWARE))
        self.assertIsNone(validate("software", n))
        self.assertEqual(n.data["version"], {"major": 9, "minor": 9})
        self.assertEqual(n.data["unparsed_version"], "OpenSSH_9.9")

    def test_missing_version_and_host_port_are_allowed(self):
        rec = json.loads(SOFTWARE)
        rec.pop("host_p")
        rec.pop("version")
        n = normalize("software", parse_line(json.dumps(rec).encode()))
        self.assertIsNone(validate("software", n))
        self.assertIsNone(n.data["host_port"])
        self.assertIsNone(n.data["version"])

    def test_missing_host_is_rejected(self):
        rec = json.loads(SOFTWARE)
        rec.pop("host")
        kind, row = run(json.dumps(rec).encode(), "software")
        self.assertEqual((kind, row["error_code"]), ("rejection", "missing_field"))
        self.assertIn("host", json.loads(row["error_details_json"]))

    def test_invalid_version_is_rejected(self):
        rec = json.loads(SOFTWARE)
        rec["version"] = {"major": "nine"}
        kind, row = run(json.dumps(rec).encode(), "software")
        self.assertEqual((kind, row["error_code"]), ("rejection", "invalid_field"))
        self.assertIn("version", json.loads(row["error_details_json"]))


class Identity(unittest.TestCase):
    def test_stable_and_probe_specific(self):
        sha = raw_sha256(HTTP)
        self.assertEqual(event_id("probe1", "conn", sha), event_id("probe1", "conn", sha))
        self.assertNotEqual(event_id("probe1", "conn", sha), event_id("probe2", "conn", sha))
        self.assertNotEqual(event_id("probe1", "conn", sha), event_id("probe1", "dhcp", sha))
        _, a = run(HTTP)
        _, b = run(HTTP)
        self.assertEqual(a["event_id"], b["event_id"])

    def test_unknown_log_type_rejected(self):
        kind, row = run(HTTP, log_type="http")
        self.assertEqual((kind, row["error_code"]), ("rejection", "unknown_log_type"))


class GoldenFixtures(unittest.TestCase):
    def test_every_real_line_is_accepted(self):
        for f in sorted(FIX.glob("*/*.log")):
            for raw in f.read_bytes().splitlines():
                kind, row = run(raw, f.stem, f.parent.name)
                self.assertEqual(kind, "observation", f"{f}: {row.get('error_details_json')}")


if __name__ == "__main__":
    unittest.main()
