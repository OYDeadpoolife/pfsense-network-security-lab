"""The synthetic sample files: reproducible, well-formed, consistent with the scenario and the rule table."""

import ipaddress
import re
import subprocess
import sys
from collections import Counter

from conftest import FILTERLOG, LINE, ROOT, SAMPLES, load_module, read_csv, read_events

ALLOWED = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "203.0.113.0/24", "198.51.100.0/24")]
generator = load_module("generate_sample_filterlog", "tools/generate_sample_filterlog.py")


def run_tool(script, *args):
    subprocess.run([sys.executable, str(ROOT / "tools" / script), *map(str, args)], check=True, capture_output=True)


def test_filterlog_is_reproducible(tmp_path):
    run_tool("generate_sample_filterlog.py", "--samples", SAMPLES, "--out", tmp_path / "log")
    assert (tmp_path / "log").read_bytes() == FILTERLOG.read_bytes()


def test_pcap_is_reproducible(tmp_path):
    run_tool("generate_synthetic_pcap.py", "--out", tmp_path / "x.pcap")
    assert (tmp_path / "x.pcap").read_bytes() == (SAMPLES / "synthetic_scan_and_ssh.pcap").read_bytes()


def test_every_line_has_the_documented_shape():
    lines = FILTERLOG.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 118
    for line in lines:
        match = LINE.match(line)
        assert match, line
        fields = match["csv"].split(",")
        assert fields[8] == "4" and fields[5] == "match" and fields[7] == "in"
        assert fields[6] in ("pass", "block")
        assert fields[16] in ("tcp", "udp", "icmp")
        assert len(fields) == (29 if fields[16] == "tcp" else 23), (len(fields), line)  # TCP has 9 protocol fields; UDP and ICMP echo have 3


def test_lines_are_in_time_order():
    stamps = [e["time"] for e in read_events()]
    assert stamps == sorted(stamps)


def test_action_totals():
    counts = Counter(e["action"] for e in read_events())
    assert counts == {"pass": 95, "block": 23}


def test_only_documentation_and_private_addresses():
    for event in read_events():
        for address in (event["src_ip"], event["dst_ip"]):
            assert any(ipaddress.ip_address(address) in network for network in ALLOWED), address


def test_rule_table_is_consistent_with_the_log():
    """Every (rule number, tracker, interface, action) in the log must come from the generator's rule table."""
    table = {(str(n), str(t), i, a) for n, t, i, a, _ in generator.RULES.values()}
    seen = {(e["rule"], e["tracker"], e["interface"], e["action"]) for e in read_events()}
    assert seen <= table
    assert len(seen) == 9  # nine different rules appear in the sample


def test_default_deny_uses_pfsenses_own_tracker():
    deny = [e for e in read_events() if e["tracker"] == "1000000103"]
    assert len(deny) == 14 and {e["action"] for e in deny} == {"block"} and {e["interface"] for e in deny} == {"em0"}


def test_scenario_events_are_present():
    events = read_events()
    scan = [e for e in events if e["src_ip"] == "198.51.100.23"]
    assert len(scan) == 14 and {e["action"] for e in scan} == {"block"}
    ssh = [e for e in events if e["src_ip"] == "203.0.113.45" and e["dst_port"] == "22"]
    assert len(ssh) == 60 and {e["dst_ip"] for e in ssh} == {"10.10.20.10"}  # the destination is the translated, inside address
    dmz = [e for e in events if e["interface"] == "em2" and e["action"] == "block"]
    assert len(dmz) == 6 and {e["dst_ip"] for e in dmz} == {"10.10.10.20"} and {e["dst_port"] for e in dmz} == {"445", "3389"}
    beacons = [e for e in events if e["dst_ip"] == "203.0.113.45" and e["dst_port"] == "443"]
    assert len(beacons) == 9


def test_source_ports_agree_with_the_scenario_csv_files():
    events = read_events()
    ssh_ports = {row["src_port"] for row in read_csv(SAMPLES / "scenario_ssh_connections.csv")}
    logged_ssh = {e["src_port"] for e in events if e["dst_port"] == "22"}
    assert logged_ssh == ssh_ports
    ws01_ports = {row["src_port"] for row in read_csv(SAMPLES / "scenario_ws01_connections.csv")}
    assert ws01_ports <= {e["src_port"] for e in events if e["src_ip"] == "10.10.10.20"}


def test_retransmissions_repeat_the_same_port_and_sequence_number():
    lines = [l for l in FILTERLOG.read_text().splitlines() if "10.10.10.20,10.10.30.50" in l]
    assert len(lines) == 3
    keys = {(l.split(",")[20], l.split(",")[24]) for l in lines}  # source port, sequence number
    assert len(keys) == 1


def test_scenario_csv_files_are_well_formed():
    ssh = read_csv(SAMPLES / "scenario_ssh_connections.csv")
    assert len(ssh) == 71 and all(re.match(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$", r["time_utc"]) for r in ssh)
    assert len(read_csv(SAMPLES / "scenario_ws01_connections.csv")) == 16


def test_no_real_looking_data_in_the_samples():
    text = FILTERLOG.read_text() + (ROOT / "samples" / "lab-expectations.csv").read_text()
    assert "orhay" + "yosef" not in text and "/Use" + "rs/" not in text
