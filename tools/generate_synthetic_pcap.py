#!/usr/bin/env python3
"""Write a small SYNTHETIC packet capture (pcap) for practising the Wireshark workflow.

THIS IS NOT A REAL CAPTURE. The packets are constructed by this script. They contain no application data
except the two public SSH identification banners ("SSH-2.0-..."), and use only documentation addresses
(RFC 5737). Nothing in the file is harmful.

What the capture shows (as seen on the firewall's WAN side, before NAT):
  * 09:12:03  198.51.100.23 sends SYN packets to ports 23, 445 and 3389 of 203.0.113.10 and never gets an answer
              (the firewall silently drops them): a blocked scan.
  * 10:02:10  203.0.113.45 completes a TCP handshake with port 22, exchanges SSH banners and closes the connection:
              an allowed connection (the port forward to web01).

The output is deterministic. Standard library only.

Usage:
    python3 tools/generate_synthetic_pcap.py --out samples/synthetic_scan_and_ssh.pcap
"""

import argparse
import struct
from datetime import datetime, timezone
from pathlib import Path

PCAP_MAGIC = 0xA1B2C3D4
LINKTYPE_ETHERNET = 1
MAC = {  # locally administered addresses (second hex digit 2) so they cannot belong to real hardware
    "198.51.100.23": bytes.fromhex("020000000023"),
    "203.0.113.45": bytes.fromhex("020000000045"),
    "203.0.113.10": bytes.fromhex("020000000010"),
}
SYN, ACK, PSH, FIN, RST = 0x02, 0x10, 0x08, 0x01, 0x04


def checksum(data):
    """The Internet checksum (RFC 1071)."""
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def ip_bytes(address):
    return bytes(int(part) for part in address.split("."))


def tcp_packet(src, sport, dst, dport, seq, ack, flags, payload=b"", mss=False, ident=1, ttl=64):
    options = b"\x02\x04\x05\xb4" if mss else b""  # maximum segment size 1460
    offset = (20 + len(options)) // 4
    header = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, offset << 4, flags, 64240, 0, 0) + options
    pseudo = ip_bytes(src) + ip_bytes(dst) + struct.pack("!BBH", 0, 6, len(header) + len(payload))
    tcp_sum = checksum(pseudo + header + payload)
    header = header[:16] + struct.pack("!H", tcp_sum) + header[18:]
    total_length = 20 + len(header) + len(payload)
    ip_header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_length, ident, 0x4000, ttl, 6, 0, ip_bytes(src), ip_bytes(dst))
    ip_header = ip_header[:10] + struct.pack("!H", checksum(ip_header)) + ip_header[12:]
    ethernet = MAC[dst] + MAC[src] + b"\x08\x00"
    return ethernet + ip_header + header + payload


def build():
    packets = []  # (epoch seconds as float, bytes)

    def add(moment, frame):
        packets.append((moment, frame))

    def epoch(hour, minute, second, micro=0):
        return datetime(2026, 3, 14, hour, minute, second, micro, tzinfo=timezone.utc).timestamp()

    # A blocked scan: each port gets a SYN and one retransmission, and no reply.
    scanner, wan = "198.51.100.23", "203.0.113.10"
    ident = 1000
    for index, port in enumerate((23, 445, 3389)):
        sport, seq = 44406 + index, 373372545 + index * 1000
        for retry, delay in enumerate((0.0, 1.0)):
            ident += 1
            add(epoch(9, 12, 3 + 2 * index) + delay, tcp_packet(scanner, sport, wan, port, seq, 0, SYN, mss=True, ident=ident, ttl=52))

    # An allowed SSH connection with a normal handshake, two banners and an orderly close.
    attacker, sport, cseq, sseq = "203.0.113.45", 57496, 1000000, 5000000
    client_banner = b"SSH-2.0-paramiko_3.4.0\r\n"
    server_banner = b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n"
    t = epoch(10, 2, 10)
    add(t, tcp_packet(attacker, sport, wan, 22, cseq, 0, SYN, mss=True, ident=2001))
    add(t + 0.0004, tcp_packet(wan, 22, attacker, sport, sseq, cseq + 1, SYN | ACK, mss=True, ident=3001))
    add(t + 0.0008, tcp_packet(attacker, sport, wan, 22, cseq + 1, sseq + 1, ACK, ident=2002))
    add(t + 0.0030, tcp_packet(wan, 22, attacker, sport, sseq + 1, cseq + 1, PSH | ACK, server_banner, ident=3002))
    add(t + 0.0034, tcp_packet(attacker, sport, wan, 22, cseq + 1, sseq + 1 + len(server_banner), PSH | ACK, client_banner, ident=2003))
    add(t + 0.0036, tcp_packet(wan, 22, attacker, sport, sseq + 1 + len(server_banner), cseq + 1 + len(client_banner), ACK, ident=3003))
    add(t + 2.5, tcp_packet(attacker, sport, wan, 22, cseq + 1 + len(client_banner), sseq + 1 + len(server_banner), FIN | ACK, ident=2004))
    add(t + 2.5004, tcp_packet(wan, 22, attacker, sport, sseq + 1 + len(server_banner), cseq + 2 + len(client_banner), FIN | ACK, ident=3004))
    add(t + 2.5008, tcp_packet(attacker, sport, wan, 22, cseq + 2 + len(client_banner), sseq + 2 + len(server_banner), ACK, ident=2005))
    return sorted(packets, key=lambda item: item[0])


def write_pcap(path, packets):
    with Path(path).open("wb") as handle:
        handle.write(struct.pack("<IHHiIII", PCAP_MAGIC, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET))
        for moment, frame in packets:
            seconds = int(moment)
            micro = int(round((moment - seconds) * 1_000_000))
            handle.write(struct.pack("<IIII", seconds, micro, len(frame), len(frame)))
            handle.write(frame)


def main():
    parser = argparse.ArgumentParser(description="Write a synthetic pcap for the Wireshark exercises.")
    parser.add_argument("--out", default="samples/synthetic_scan_and_ssh.pcap")
    args = parser.parse_args()
    packets = build()
    write_pcap(args.out, packets)
    print(f"wrote {args.out} ({len(packets)} packets)")


if __name__ == "__main__":
    main()
