#!/usr/bin/env python3
"""Derive the connection lists that make the firewall log match the other portfolio projects.

SYNTHETIC DATA ONLY. The firewall log of this lab imitates the same fictional day as the SOC lab
and the log-analysis toolkit. To make the three sources agree, the firewall generator needs the
source ports and times of the SSH connections (from an auth.log) and of the Windows client's
connections (from Sysmon events). This script extracts them. The two small CSV files it writes
are committed in samples/, so you only need to run it if you change the scenario.

Usage:
    python3 tools/extract_scenario_connections.py --auth-log AUTH_LOG --sysmon SYSMON_JSONL --out-dir samples
"""

import argparse
import csv
import json
import re
from datetime import datetime, timezone
from pathlib import Path

YEAR = 2026
MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
SSH_LINE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d+)\s+(?P<clock>\d\d:\d\d:\d\d)\s+\S+\s+sshd\[\d+\]:\s+"
    r"(?:Invalid user \S+|Failed \w+ for (?:invalid user )?\S+|Accepted \w+ for \S+) from (?P<ip>\S+) port (?P<port>\d+)"
)


def ssh_connections(auth_log):
    """One row per SSH connection: the first log line that mentions its (address, port)."""
    seen, rows = set(), []
    for line in Path(auth_log).read_text(encoding="utf-8").splitlines():
        match = SSH_LINE.match(line)
        if not match or (match["ip"], match["port"]) in seen:
            continue
        seen.add((match["ip"], match["port"]))
        stamp = datetime(YEAR, MONTHS.index(match["mon"]) + 1, int(match["day"]), *map(int, match["clock"].split(":")), tzinfo=timezone.utc)
        rows.append({"time_utc": stamp.strftime("%Y-%m-%dT%H:%M:%SZ"), "src_ip": match["ip"], "src_port": match["port"], "dst_ip": "10.10.20.10", "dst_port": "22"})
    return rows


def ws01_connections(sysmon_jsonl):
    """One row per network connection initiated by the Windows client (Sysmon event 3)."""
    rows = []
    for line in Path(sysmon_jsonl).read_text(encoding="utf-8").splitlines():
        event = json.loads(line)
        if event["EventCode"] != 3:
            continue
        rows.append({"time_utc": event["UtcTime"].replace(" ", "T")[:23] + "Z", "src_ip": event["SourceIp"], "src_port": event["SourcePort"],
                     "dst_ip": event["DestinationIp"], "dst_port": event["DestinationPort"], "process": event["Image"].rsplit("\\", 1)[-1]})
    return rows


def write_csv(path, rows):
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser(description="Extract connection lists from the synthetic auth.log and Sysmon data.")
    parser.add_argument("--auth-log", required=True)
    parser.add_argument("--sysmon", required=True, help="sysmon_native.jsonl")
    parser.add_argument("--out-dir", default="samples")
    args = parser.parse_args()
    out = Path(args.out_dir)
    ssh, ws01 = ssh_connections(args.auth_log), ws01_connections(args.sysmon)
    write_csv(out / "scenario_ssh_connections.csv", ssh)
    write_csv(out / "scenario_ws01_connections.csv", ws01)
    print(f"wrote {len(ssh)} SSH connections and {len(ws01)} WS01 connections to {out}")


if __name__ == "__main__":
    main()
