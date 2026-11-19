# Packet analysis with Wireshark

A firewall log tells you *that* a connection was allowed or blocked. A packet capture shows *what the packets did*. This page is a workflow, with a **synthetic**
capture (`samples/synthetic_scan_and_ssh.pcap`) to practise on. The capture is constructed by `tools/generate_synthetic_pcap.py`; it is **not a real capture**,
contains no application data except two public SSH banners, and uses only documentation addresses. Its checksums were verified with `tcpdump`; it has **not** been opened in Wireshark by the author.

## 1. Capture (only in your own lab)

| Where | How | Notes |
|---|---|---|
| On pfSense | Diagnostics > Packet Capture: choose the interface (for example WAN), optionally the host and port, set a packet count, **Start**, reproduce the traffic, **Stop**, **Download Capture** | Capturing on the WAN shows the packet *before* NAT (destination `203.0.113.10:22`); on the DMZ interface it shows the *inside* address `10.10.20.10:22` |
| On a Linux VM | `sudo tcpdump -i ens33 -nn -w capture.pcap 'host 203.0.113.45 and tcp port 22'` | `-i` interface, `-nn` no name or port-name lookups, `-w` write a file, the quoted text is a capture filter. Needs root; it changes nothing on the system. Stop with Ctrl+C: it prints `N packets captured` |
| In Wireshark | Capture > Interfaces, double-click the interface, optionally set a capture filter | On Windows install Npcap with Wireshark |

**Privacy:** a capture can contain passwords and personal data. Keep your own captures private; this repository only contains a synthetic one.

## 2. Open and orient

1. File > Open `samples/synthetic_scan_and_ssh.pcap`. Expected: **15 packets**.
2. View > Time Display Format > **UTC Date and Time of Day**. By default Wireshark shows your local time zone, so the first packet would not read `09:12:03`.
3. Statistics > **Conversations** > TCP tab: expected **4 conversations**: three `198.51.100.23` to ports 23, 445, 3389 and one `203.0.113.45:57496` to port 22.
4. Statistics > Protocol Hierarchy: all TCP over IPv4 over Ethernet; two packets carry SSH.

## 3. Display filters

| Goal | Filter | Expected on the sample |
|---|---|---|
| Everything from the scanner | `ip.src == 198.51.100.23` | 6 packets |
| Start of connections (SYN without ACK) | `tcp.flags.syn == 1 && tcp.flags.ack == 0` | 7 packets (6 scan probes + 1 SSH) |
| Answers to a SYN (SYN-ACK) | `tcp.flags.syn == 1 && tcp.flags.ack == 1` | 1 packet, from `203.0.113.10:22` |
| One service | `tcp.port == 22` | 9 packets |
| SSH banners | `ssh` | 2 packets (server and client identification) |
| A single conversation | `tcp.stream == 3` | 9 packets (the SSH connection) |
| Retransmitted SYNs | `tcp.analysis.retransmission` | The second SYN of each probe is typically flagged. *Expected, not verified in Wireshark* |
| VLAN-tagged frames | `vlan.id == 20` | none in this capture |

## 4. Read the patterns

| What you see | What it means |
|---|---|
| SYN, then **nothing** (the same SYN again a second later) | The packet was dropped silently, or the host is unreachable: **blocked by the default deny**. pfSense's default block action drops without answering. This is the scanner's pattern |
| SYN, then **RST/ACK** | The packet reached a host that has no service on that port ("closed"), or the firewall used *reject* instead of *block* |
| SYN, **SYN-ACK**, ACK | A normal handshake: the port is open and the connection is **allowed** |
| Data packets right after the handshake | Application data. In the sample, the two SSH identification banners (`SSH-2.0-...`) |
| FIN/ACK in both directions | A clean close |
| Many short connections to the same port from one source | Brute force or scanning: count them with Statistics > Conversations |

Right-click a packet > **Follow > TCP Stream** to read the banners: Expected text `SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13` (server) and `SSH-2.0-paramiko_3.4.0` (client).

## 5. Compare with the firewall log

| Capture (UTC) | Firewall log (`samples/filterlog_sample.log`) |
|---|---|
| `09:12:03` SYN `198.51.100.23:44406` to `203.0.113.10:23`, repeated at `09:12:04` | `09:12:03` and `09:12:04`, `block`, `em0`, rule 12, tracker `1000000103`, same ports |
| `10:02:10` SYN `203.0.113.45:57496` to `203.0.113.10:22`, then SYN-ACK and ACK | `10:02:10`, `pass`, `em0`, rule 98, destination **`10.10.20.10:22`** (translated), source port `57496` |
| — | `auth.log` on web01: `10:02:11 ... Invalid user admin from 203.0.113.45 port 57496` |

The same source port ties the capture, the firewall log and the server log together. The firewall log shows the destination **after** NAT, the capture on the WAN shows it **before**.

## 6. Real output of `tcpdump` on the sample

```bash
TZ=UTC tcpdump -nn -tttt -r samples/synthetic_scan_and_ssh.pcap | head -9
```

```text
2026-03-14 09:12:03.000000 IP 198.51.100.23.44406 > 203.0.113.10.23: Flags [S], seq 373372545, win 64240, options [mss 1460], length 0
2026-03-14 09:12:04.000000 IP 198.51.100.23.44406 > 203.0.113.10.23: Flags [S], seq 373372545, win 64240, options [mss 1460], length 0
2026-03-14 09:12:05.000000 IP 198.51.100.23.44407 > 203.0.113.10.445: Flags [S], seq 373373545, win 64240, options [mss 1460], length 0
...
2026-03-14 10:02:10.000000 IP 203.0.113.45.57496 > 203.0.113.10.22: Flags [S], seq 1000000, win 64240, options [mss 1460], length 0
2026-03-14 10:02:10.000400 IP 203.0.113.10.22 > 203.0.113.45.57496: Flags [S.], seq 5000000, ack 1000001, win 64240, options [mss 1460], length 0
2026-03-14 10:02:10.000800 IP 203.0.113.45.57496 > 203.0.113.10.22: Flags [.], ack 1, win 64240, length 0
```

(`-r` reads a file, `-tttt` prints full dates, `[S]` is SYN, `[S.]` SYN-ACK, `[.]` ACK, `[P.]` data, `[F.]` FIN.) This command only reads the file.

## 7. Common pitfalls

* **"Bad checksum" warnings on captures taken inside a VM:** the network card may calculate checksums after the capture point (checksum offload). The packets are fine; in
  Wireshark turn off *Validate the TCP checksum* (Edit > Preferences > Protocols > TCP).
* **Capturing on the wrong interface:** a packet blocked on the WAN never reaches the DMZ interface. Capture where you expect the packet to be.
* **Time zones:** compare capture, firewall and server logs in UTC.
* **Large captures:** limit them with a capture filter and a packet count.
