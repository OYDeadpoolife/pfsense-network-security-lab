"""Shared helpers for the pfSense lab tests."""

import csv
import importlib.util
import os
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"
FILTERLOG = SAMPLES / "filterlog_sample.log"
SUMMARY = ROOT / "scripts" / "filterlog_summary.sh"
CONNECTIVITY = ROOT / "scripts" / "lab_connectivity_test.sh"

# A line of the BSD-format filter.log.
LINE = re.compile(r"^(?P<time>[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d) (?P<host>\S+) filterlog\[(?P<pid>\d+)\]: (?P<csv>.*)$")


def load_module(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def parse_line(line):
    """Independent Python parser of an IPv4 filterlog line (does not share code with filterlog.awk)."""
    match = LINE.match(line)
    fields = match["csv"].split(",")
    proto = fields[16]
    event = {"time": match["time"], "rule": fields[0], "tracker": fields[3], "interface": fields[4], "action": fields[6],
             "direction": fields[7], "ip_version": fields[8], "protocol": proto, "src_ip": fields[18], "dst_ip": fields[19],
             "src_port": "-", "dst_port": "-", "detail": "-"}
    if proto in ("tcp", "udp"):
        event["src_port"], event["dst_port"] = fields[20], fields[21]
        if proto == "tcp":
            event["detail"] = fields[23]
    elif proto == "icmp":
        event["detail"] = fields[20]
    return event


def read_events(path=FILTERLOG):
    return [parse_line(line) for line in Path(path).read_text(encoding="utf-8").splitlines()]


def read_csv(path):
    with Path(path).open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(line for line in handle if not line.startswith("#")))


@pytest.fixture
def summary(tmp_path):
    def run(*args, stdin=None, env_extra=None):
        env = dict(os.environ, TMPDIR=str(tmp_path))
        env.update(env_extra or {})
        return subprocess.run([str(SUMMARY), *map(str, args)], input=stdin, capture_output=True, env=env, timeout=60)
    return run
