"""The synthetic packet capture: valid pcap structure, correct checksums, and the numbers quoted in docs/packet-analysis.md."""

import shutil
import struct
import subprocess

import pytest

from conftest import ROOT, SAMPLES

PCAP = SAMPLES / "synthetic_scan_and_ssh.pcap"


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def read_packets():
    data = PCAP.read_bytes()
    magic, major, minor, _, _, snaplen, linktype = struct.unpack("<IHHiIII", data[:24])
    assert (magic, major, minor, linktype) == (0xA1B2C3D4, 2, 4, 1)
    packets, offset = [], 24
    while offset < len(data):
        seconds, micro, captured, original = struct.unpack("<IIII", data[offset:offset + 16])
        frame = data[offset + 16:offset + 16 + captured]
        assert captured == original == len(frame)
        packets.append((seconds + micro / 1e6, frame))
        offset += 16 + captured
    return packets


def decode(frame):
    assert frame[12:14] == b"\x08\x00"
    ip = frame[14:]
    header_length = (ip[0] & 15) * 4
    total_length = struct.unpack("!H", ip[2:4])[0]
    src, dst = ".".join(map(str, ip[12:16])), ".".join(map(str, ip[16:20]))
    tcp = ip[header_length:total_length]
    sport, dport, seq, ack, offset_flags, window = struct.unpack("!HHIIHH", tcp[:16])
    flags = offset_flags & 0x3F
    payload = tcp[(offset_flags >> 12) * 4:]
    pseudo = ip[12:20] + struct.pack("!BBH", 0, 6, len(tcp))
    return {"src": src, "dst": dst, "sport": sport, "dport": dport, "flags": flags, "payload": payload, "ip_ok": checksum(ip[:header_length]) == 0,
            "tcp_ok": checksum(pseudo + tcp) == 0, "ttl": ip[8]}


def test_file_structure_and_packet_count():
    assert len(read_packets()) == 15


def test_all_checksums_are_valid_and_addresses_are_documentation_ranges():
    for _, frame in read_packets():
        packet = decode(frame)
        assert packet["ip_ok"] and packet["tcp_ok"]
        assert packet["src"].startswith(("198.51.100.", "203.0.113.")) and packet["dst"].startswith(("198.51.100.", "203.0.113."))


def test_timestamps_increase():
    stamps = [t for t, _ in read_packets()]
    assert stamps == sorted(stamps)


def test_numbers_quoted_in_the_documentation():
    packets = [decode(frame) for _, frame in read_packets()]
    assert sum(p["src"] == "198.51.100.23" for p in packets) == 6
    assert sum(p["flags"] & 0x12 == 0x02 for p in packets) == 7  # SYN without ACK
    assert sum(p["flags"] & 0x12 == 0x12 for p in packets) == 1  # SYN-ACK
    assert sum(22 in (p["sport"], p["dport"]) for p in packets) == 9
    assert {p["dport"] for p in packets if p["src"] == "198.51.100.23"} == {23, 445, 3389}
    assert sum(1 for p in packets if p["payload"].startswith(b"SSH-2.0-")) == 2
    conversations = {tuple(sorted([(p["src"], p["sport"]), (p["dst"], p["dport"])])) for p in packets}
    assert len(conversations) == 4


def test_the_scan_gets_no_answer_and_the_ssh_connection_is_complete():
    packets = [decode(frame) for _, frame in read_packets()]
    assert not [p for p in packets if p["dst"] == "198.51.100.23"], "the blocked scanner must receive nothing"
    ssh = [p for p in packets if 22 in (p["sport"], p["dport"])]
    assert [p["flags"] for p in ssh] == [0x02, 0x12, 0x10, 0x18, 0x18, 0x10, 0x11, 0x11, 0x10]  # handshake, banners, close


def test_capture_matches_the_firewall_log_and_the_scenario():
    from conftest import read_events

    packets = [decode(frame) for _, frame in read_packets()]
    ssh_port = next(p["sport"] for p in packets if p["dport"] == 22)
    logged = [e for e in read_events() if e["src_port"] == str(ssh_port)]
    assert len(logged) == 1 and logged[0]["action"] == "pass" and logged[0]["time"] == "Mar 14 10:02:10"
    scan_ports = {str(p["sport"]) for p in packets if p["src"] == "198.51.100.23"}
    assert scan_ports <= {e["src_port"] for e in read_events() if e["src_ip"] == "198.51.100.23"}


@pytest.mark.skipif(shutil.which("tcpdump") is None, reason="tcpdump is not installed")
def test_tcpdump_can_read_the_file_and_confirms_the_checksums():
    completed = subprocess.run(["tcpdump", "-nn", "-v", "-r", str(PCAP)], capture_output=True, text=True)
    output = completed.stdout + completed.stderr
    assert completed.returncode == 0
    assert output.count("cksum") >= 15 and "(correct)" in output and "incorrect" not in output
