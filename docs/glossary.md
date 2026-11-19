# Glossary (plain language)

If you are new to networking and firewall terms, this page explains the words used in this repository.

| Term | Meaning |
|---|---|
| Firewall | A system that decides which network connections are allowed and which are blocked. |
| pfSense | Free, open-source firewall and router software. |
| WAN / LAN / DMZ / MGMT | The four zones of the lab. WAN is the outside (here a simulated Internet). LAN is the internal office network. The DMZ (demilitarised zone) is a separate area for servers that must be reachable from outside. MGMT is the management network used for administration and monitoring. |
| Firewall rule (pass / block) | A line that says whether one kind of connection is allowed (pass) or refused (block). |
| NAT | Network address translation: the firewall shows one outside address and forwards connections to the right machine inside. |
| VLAN | A way to split one physical network into several separate virtual ones. |
| Syslog | A standard way to send log lines to another computer. |
| SIEM | A central system that collects logs from many sources and lets you search them. |
| `filterlog` | The name of pfSense's firewall log format. The scripts in this repository read it. |
| Packet capture (pcap) | A recording of network traffic. |
| Wireshark | A free program for reading packet captures. |
| SYN / port scan | A SYN packet is the first step of opening a TCP connection. Many SYN packets to many ports from one address is what a port scan looks like. |
| Bogon | An address range that should not appear on the public Internet. Firewalls can block such traffic. |
| Synthetic data | Made-up data. The firewall log and the packet capture in this repository are synthetic. |
