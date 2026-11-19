# Troubleshooting cases

> **Status:** written from the design and general pfSense knowledge; **none of these cases was reproduced on a real pfSense** by the author. Each case shows the
> symptom, how to confirm it in the firewall log or the GUI, the likely cause and the fix. Where the sample log demonstrates the confirmation, it is noted.

| # | Symptom | How to confirm | Likely cause | Fix |
|---|---|---|---|---|
| 1 | SSH to the WAN address times out (T30 fails) | Firewall log: a `block` on `em0` with destination `10.10.20.10:22` and the default deny tracker `1000000103`, or no line at all | The port forward has no associated WAN rule, the rule is disabled or below another rule; or web01's SSH service is not running | Edit the port forward and use *Add associated filter rule*; check the rule on Firewall > Rules > WAN; start sshd |
| 2 | The firewall log shows `pass`, but the connection still fails | Log says `pass` for the SYN, but there is no SYN-ACK in a capture on web01 | Reply path: web01's default gateway is not pfSense (asymmetric routing), or a host firewall on web01 drops the packets | Set web01's gateway to `10.10.20.1`; check `ufw status` and the service's listening address |
| 3 | The forward works from kali01 but not from inside by the WAN address | Works with `10.10.20.10`, not with `203.0.113.10` | NAT reflection is off (normal default) | Use the inside address, or enable NAT reflection for that rule |
| 4 | The DMZ server can reach the LAN (T10 or T11 fails with `allow`) | Log lines on `em2` with `pass` and a rule number other than the DMZ block rule | A "pass any" rule above the block rule (order), or the block rule was created on the wrong interface tab, or a floating rule overrides it | Move the block rule to the top of the DMZ tab; check Firewall > Rules > Floating |
| 5 | Nothing from the LAN works | Log: `block` lines on `em1` for DNS or web traffic with the default deny tracker | The LAN rules are missing (a new interface has no allow rule) or the rule's source is wrong | Re-create the LAN rules; remember that only the default LAN has an "allow all" rule on a fresh install |
| 6 | Ping to the firewall fails but TCP works (T01) | A capture on WS01 shows echo requests and no replies; the log has no `block` | The Windows firewall drops incoming echo, or the ICMP rule is missing | Allow echo in the host firewall or add LAN rule 2 |
| 7 | Traffic from the lab's `203.0.113.0/24` is blocked on the WAN even when a pass rule exists | `block` lines on `em0` that do not name the default deny tracker | **Block bogon networks** (or **Block private networks**) is ticked on the WAN | Untick it for the isolated lab only; re-enable it in real deployments |
| 8 | The pfSense web interface answers from the WAN (T32 reports `allow`) | A capture from kali01 shows a TLS handshake with `203.0.113.10:443` | A WAN "pass any" rule, or the GUI listens on WAN with a rule that allows it | Remove the rule; the default deny must handle everything else on the WAN |
| 9 | Only `block` events are visible, no `pass` events | The log shows no lines for traffic you know is allowed | *Log* is not ticked on the pass rules (only the default deny logs by default) | Edit the rule, tick *Log packets that are handled by this rule* |
| 10 | The SIEM shows no firewall events | `tcpdump -i any -nn udp port 5514` on siem01 shows nothing | Remote logging is off, wrong address or port, or UDP blocked by a host firewall | See [siem-integration.md](siem-integration.md) |
| 11 | The firewall events are hours off in the SIEM | Compare with the GUI | BSD syslog has no time zone; the SIEM assumed another one | Set the zone on the input, or use RFC 5424 |
| 12 | A test that expects `allow` fails although the rules are right | The firewall log shows `pass`, and nothing listens on the target | No service is listening on that port | Start a temporary listener (see [connectivity-tests.md](connectivity-tests.md)) |
| 13 | VLAN interface has no connectivity | `ip -d link show` on the VM shows the tag; a capture on the trunk shows no tagged frames | The virtual switch strips tags, the VLAN interface is not enabled in pfSense, or the parent interface is wrong | Use separate virtual networks (Option 1) or check the hypervisor's VLAN support |
| 14 | An interface is down or has the wrong address after boot | The console menu shows the interface mapping; the dashboard shows "no carrier" | The VM's adapters are in a different order than the assignment, or an adapter is disconnected | Compare the adapter order in the VM settings with the console assignment (`em0`-`em3`) and fix |

## A method for any "it does not work" problem

1. **Ping the next hop** (the pfSense address of your zone), then the destination. Where does it stop?
2. **Read the firewall log** for the destination: is there a `block`, a `pass`, or no line? A `block` names the rule; no line means it never reached the firewall or the rule does not log.
3. **Capture on both sides** of the firewall (the two interfaces involved) and compare: does the SYN arrive? Does it leave? Does a SYN-ACK come back?
4. **Check the host**: is the service listening (`ss -ltn`), is the host firewall allowing it, is the gateway right?
5. **Change one thing at a time** and write down the result.

## Running the scripts of this repository

| Symptom | Cause | Fix |
|---|---|---|
| `Permission denied` when running `./scripts/filterlog_summary.sh` | The executable bit was lost (for example by a web upload to GitHub) | `chmod +x scripts/*.sh`, or run `bash scripts/filterlog_summary.sh ...` |
| `nc: command not found` in the connectivity test | netcat is not installed | Install it in the lab VM (`sudo apt install netcat-openbsd` on Debian/Ubuntu/Kali) |
| `refusing target ...` | A line of the expectations file names an address outside `10.10.0.0/16` and `203.0.113.0/24` | That is the safety check working: correct the file, never bypass it |
