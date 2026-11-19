#!/usr/bin/env python3
"""Generate a SYNTHETIC pfSense firewall log for the fictional "Harbor Lab" day.

THIS FILE WAS NOT CAPTURED FROM A REAL FIREWALL. Every line is constructed by this script,
following the documented pfSense "filterlog" CSV format (Netgate documentation, "Raw Filter Log
Format"). Hosts, addresses, rule numbers and tracker IDs are invented. Addresses come from the
RFC 5737 documentation ranges or from private ranges.

The log imitates /var/log/filter.log in the default BSD syslog format:

    Mar 14 09:12:03 pfsense-lab filterlog[84921]: 12,,,1000000103,em0,match,block,in,4,0x0,,52,41234,0,none,6,tcp,60,198.51.100.23,203.0.113.10,54321,23,0,S,2845117301,,64240,,mss;sackOK;TS;nop;wscale

The SSH and Windows-client connections are read from samples/scenario_*.csv (derived from the
other portfolio projects' data) so that source ports and times agree across the firewall log,
auth.log and Sysmon. The output is deterministic.

Usage:
    python3 tools/generate_sample_filterlog.py --out samples/filterlog_sample.log
"""

import argparse
import csv
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

SEED = 20260314
HOST = "pfsense-lab"
FILTERLOG_PID = 84921
WAN_ADDRESS = "203.0.113.10"
INCIDENT_DAY = datetime(2026, 3, 14, tzinfo=timezone.utc)

# key -> (pf rule number, tracker ID, interface, action, description)
# Real rule numbers and trackers differ in every installation: map yours with Status > System Logs > Firewall
# (click the rule number) or by searching /tmp/rules.debug for the tracker. 1000000103 is pfSense's own
# "Default deny rule IPv4"; the other trackers are invented.
RULES = {
    "wan_default_deny": (12, 1000000103, "em0", "block", "Default deny rule IPv4 (WAN)"),
    "wan_ssh_nat": (98, 1710410101, "em0", "pass", "NAT port forward: WAN 22 -> web01 22"),
    "lan_dns": (61, 1710410201, "em1", "pass", "LAN net -> firewall DNS 53"),
    "lan_icmp": (62, 1710410202, "em1", "pass", "LAN net -> any ICMP echo"),
    "lan_block_mgmt": (63, 1710410203, "em1", "block", "LAN net -> MGMT net (block)"),
    "lan_web_dmz": (64, 1710410204, "em1", "pass", "LAN net -> DMZ net 80,443"),
    "lan_web_egress": (65, 1710410205, "em1", "pass", "LAN net -> not RFC1918 80,443"),
    "lan_default_deny": (12, 1000000103, "em1", "block", "Default deny rule IPv4 (LAN)"),
    "dmz_block_lan": (71, 1710410301, "em2", "block", "DMZ net -> LAN net (block)"),
    "dmz_to_siem": (72, 1710410302, "em2", "pass", "DMZ web01 -> siem01 5044,9997"),
    "mgmt_ssh": (81, 1710410401, "em3", "pass", "MGMT SSH sources -> DMZ 22"),
}

WINDOWS_OPTIONS = "mss;nop;wscale;nop;nop;sackOK"
LINUX_OPTIONS = "mss;sackOK;TS;nop;wscale"


def stamp(moment):
    return f"{moment.strftime('%b')} {moment.day:>2} {moment.strftime('%H:%M:%S')}"


class FilterLog:
    def __init__(self, rng):
        self.rng = rng
        self.lines = []  # (time, order, text)

    def _ipv4(self, proto_id, proto_name, length, src, dst, ttl):
        ident = self.rng.randint(1, 65535)
        return f"4,0x0,,{ttl},{ident},0,DF,{proto_id},{proto_name},{length},{src},{dst}"

    def _emit(self, moment, rule_key, ip_part, protocol_part):
        number, tracker, interface, action, _ = RULES[rule_key]
        text = f"{number},,,{tracker},{interface},match,{action},in,{ip_part},{protocol_part}"
        self.lines.append((moment, len(self.lines), f"{stamp(moment)} {HOST} filterlog[{FILTERLOG_PID}]: {text}"))

    def tcp_syn(self, moment, rule_key, src, sport, dst, dport, ttl=64, options=LINUX_OPTIONS, seq=None):
        seq = seq if seq is not None else self.rng.randint(1, 2**32 - 1)
        ip_part = self._ipv4(6, "tcp", 60, src, dst, ttl)
        self._emit(moment, rule_key, ip_part, f"{sport},{dport},0,S,{seq},,64240,,{options}")
        return seq

    def udp(self, moment, rule_key, src, sport, dst, dport, payload=32, ttl=128):
        ip_part = self._ipv4(17, "udp", 28 + payload, src, dst, ttl)
        self._emit(moment, rule_key, ip_part, f"{sport},{dport},{payload}")

    def icmp_echo(self, moment, rule_key, src, dst, identifier, sequence, ttl=128):
        ip_part = self._ipv4(1, "icmp", 84, src, dst, ttl)
        self._emit(moment, rule_key, ip_part, f"request,{identifier},{sequence}")

    def render(self):
        return "\n".join(text for _, _, text in sorted(self.lines)) + "\n"


def at(hour, minute, second=0):
    return INCIDENT_DAY.replace(hour=hour, minute=minute, second=second)


def parse_time(text):
    return datetime.strptime(text.rstrip("Z"), "%Y-%m-%dT%H:%M:%S.%f" if "." in text else "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)


def read_rows(path):
    with Path(path).open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def build(samples_dir):
    rng = random.Random(SEED)
    log = FilterLog(rng)
    samples_dir = Path(samples_dir)

    # Log shipping from web01 to the SIEM: one connection at start-up and one reconnect.
    for moment in (at(0, 0, 30), at(10, 30, 1)):
        log.tcp_syn(moment, "dmz_to_siem", "10.10.20.10", rng.randint(40000, 60000), "10.10.30.50", 5044)

    # Every SSH connection of the day (times and ports come from auth.log). The SYN arrives a second before sshd logs it.
    for row in read_rows(samples_dir / "scenario_ssh_connections.csv"):
        moment = parse_time(row["time_utc"]) - timedelta(seconds=1)
        external = row["src_ip"].startswith("203.0.113.")
        # pf rewrites the destination of a port-forwarded packet BEFORE filtering, so the log shows the inside address.
        log.tcp_syn(moment, "wan_ssh_nat" if external else "mgmt_ssh", row["src_ip"], int(row["src_port"]), row["dst_ip"], int(row["dst_port"]))

    # The Windows client's connections (times and ports come from Sysmon).
    for row in read_rows(samples_dir / "scenario_ws01_connections.csv"):
        moment = parse_time(row["time_utc"]) - timedelta(milliseconds=300)
        moment = moment.replace(microsecond=0)
        if row["dst_ip"] == "10.10.10.1" and row["dst_port"] == "53":
            log.tcp_syn(moment, "lan_dns", row["src_ip"], int(row["src_port"]), row["dst_ip"], 53, ttl=128, options=WINDOWS_OPTIONS)
        else:
            log.tcp_syn(moment, "lan_web_egress", row["src_ip"], int(row["src_port"]), row["dst_ip"], int(row["dst_port"]),
                        ttl=128, options=WINDOWS_OPTIONS)

    # DNS over UDP from the client (normal background traffic).
    for moment in (at(8, 52, 9), at(9, 40, 8), at(11, 29, 40)):
        log.udp(moment, "lan_dns", "10.10.10.20", rng.randint(49152, 65000), "10.10.10.1", 53)

    # 09:12 - an Internet scanner probes ports that are not forwarded: every probe is blocked by the default rule.
    sport_base = rng.randint(30000, 60000)
    for index, dport in enumerate((23, 445, 3389, 8080, 5900, 3306, 1433, 21, 25, 110)):
        moment = at(9, 12, 3) + timedelta(seconds=index * 2)
        seq = log.tcp_syn(moment, "wan_default_deny", "198.51.100.23", sport_base + index, WAN_ADDRESS, dport, ttl=52)
        if index % 3 == 0:  # nmap retransmits some probes when there is no answer
            log.tcp_syn(moment + timedelta(seconds=1), "wan_default_deny", "198.51.100.23", sport_base + index, WAN_ADDRESS, dport, ttl=52, seq=seq)

    # 09:30 - a user tries to open the SIEM web interface from the LAN: blocked by the LAN-to-MGMT rule (a benign mistake).
    port = rng.randint(49152, 65000)
    seq = rng.randint(1, 2**32 - 1)
    for offset in (0, 3, 9):  # Windows retransmits a SYN after 3 and 6 more seconds
        log.tcp_syn(at(9, 30, 10) + timedelta(seconds=offset), "lan_block_mgmt", "10.10.10.20", port, "10.10.30.50", 8000,
                    ttl=128, options=WINDOWS_OPTIONS, seq=seq)

    # 10:15 - the compromised web server tries to reach the workstation: blocked by the DMZ-to-LAN rule.
    for dport, start in ((445, at(10, 15, 2)), (3389, at(10, 15, 20))):
        port = rng.randint(40000, 60000)
        seq = rng.randint(1, 2**32 - 1)
        for offset in (0, 1, 3):
            log.tcp_syn(start + timedelta(seconds=offset), "dmz_block_lan", "10.10.20.10", port, "10.10.10.20", dport, seq=seq)

    # 12:00 - ping tests from the client.
    log.icmp_echo(at(12, 0, 5), "lan_icmp", "10.10.10.20", "10.10.10.1", 1, 1)
    log.icmp_echo(at(12, 0, 6), "lan_icmp", "10.10.10.20", "10.10.10.1", 1, 2)
    log.icmp_echo(at(12, 1, 10), "lan_icmp", "10.10.10.20", "10.10.20.10", 2, 1)
    return log


def main():
    parser = argparse.ArgumentParser(description="Generate a synthetic pfSense filter.log.")
    parser.add_argument("--samples", default="samples", help="folder with the scenario_*.csv files (default: samples)")
    parser.add_argument("--out", default="samples/filterlog_sample.log", help="output file")
    args = parser.parse_args()
    text = build(args.samples).render()
    with Path(args.out).open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    print(f"wrote {args.out} ({text.count(chr(10))} lines)")


if __name__ == "__main__":
    main()
