# Screenshot checklist

These screenshots can only come from your running lab; none exists yet and **none may be faked**. Take each one after the step it belongs to, save it with exactly this name
in this folder and remove the comment markers around the matching line in the main `README.md`.

| File | Open | Do | What must be visible |
|---|---|---|---|
| `01-topology.png` | The README on GitHub (or the VMware Virtual Network Editor) | Show the topology diagram, or the four virtual networks | The four zones and the pfSense machine. Proves the design renders / the networks exist |
| `02-firewall-rules.png` | pfSense Firewall > Rules, one tab at a time (take WAN, LAN, DMZ and MGMT, or stitch them) | Show the rule lists | The rules in the order of `docs/firewall-policy.md`, with the log icons and the associated WAN SSH rule |
| `03-firewall-log.png` | pfSense Status > System Logs > Firewall | Generate one allowed and one blocked connection first (Step 8 of the setup guide) | At least one `pass` and one `block` line with interface, source, destination and port |
| `04-wireshark.png` | Wireshark with your own capture, or `samples/synthetic_scan_and_ssh.pcap` | Apply `tcp.flags.syn == 1 && tcp.flags.ack == 0` | The SYN packets and the time column in UTC. **If you use the synthetic file, say so in the README caption** |
| `05-connectivity-tests.png` | A terminal on a lab machine | `./scripts/lab_connectivity_test.sh --zone DMZ --confirm-lab` | The `PASS`/`FAIL` lines and the summary. Only a real run on a real lab counts |
| `06-siem-firewall-events.png` | Your SIEM's search page | Search the `pfsense:filterlog` events | Firewall events arriving from pfSense, with parsed fields |

Embed with: `![Firewall log](screenshots/03-firewall-log.png)`

Before uploading, crop or blur anything personal (your user name, real addresses, licence keys, the pfSense admin credentials). If a screenshot is not
from a real run of this lab, do not include it.
