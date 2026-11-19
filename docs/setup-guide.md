# Setup guide

> **Status:** instructions. **The author has not built this lab yet**, so the steps are *not verified* on a running pfSense. They are based on the
> pfSense documentation and general experience; menu names can differ between versions. Record what you really see in [TEST_RESULTS.md](../TEST_RESULTS.md).

## Safety rules (read first)

* Keep the lab on **isolated virtual networks** (host-only or LAN-segment type). Do **not** bridge any lab adapter to your home network.
* Do **not** forward ports on your real router, expose services to the Internet or scan any network you do not own.
* The attacker/test machine (`kali01`) is only used against the lab's own `203.0.113.10` and `10.10.x.x` addresses.
* Take **snapshots** before changing a VM, so you can go back.

## Choose your path

| Path | What you do | Result |
|---|---|---|
| **A. Documentation-only** | Use the sample log and capture: `scripts/filterlog_summary.sh`, Wireshark on `samples/synthetic_scan_and_ssh.pcap` | Works now; no VMs; nothing about a real pfSense is verified |
| **B. VM-based** | Build the lab below and verify it with the tests | Real, verified results *that you record yourself* |

## Path B prerequisites

* A computer with **VMware Workstation** (or similar) and about 16 GB RAM (the machines above need roughly 10-14 GB if all run at once; run fewer for a smaller test).
* **An x86-64 processor.** pfSense CE has no image for a generic ARM computer such as an Apple Silicon Mac (see the README). On such a Mac you would need emulation, which is slow and not covered here.
* Installation images: pfSense CE from [pfsense.org/download](https://www.pfsense.org/download/), Ubuntu Server, Kali Linux and a Windows evaluation image from their official sources. Check each licence.
* Optional: Splunk or an Elastic Stack for `siem01`.

## Step 1 - Virtual networks

Create four isolated virtual networks (VMware: Virtual Network Editor; pick *host-only* networks with the VMware DHCP service **disabled**):

| Network | Subnet | Used by |
|---|---|---|
| `WAN-SIM` | `203.0.113.0/24` | pfSense `em0`, kali01 |
| `LAN-NET` | `10.10.10.0/24` | pfSense `em1`, WS01 |
| `DMZ-NET` | `10.10.20.0/24` | pfSense `em2`, web01 |
| `MGMT-NET` | `10.10.30.0/24` | pfSense `em3`, siem01, jump01 |

Expected result: four networks, no DHCP service, none bridged.

## Step 2 - pfSense VM

1. Create a FreeBSD 64-bit VM (1 vCPU, 1 GB RAM, 8 GB disk) with **four** network adapters in the order WAN-SIM, LAN-NET, DMZ-NET, MGMT-NET (so they become `em0`-`em3`).
2. Install pfSense CE from the ISO with the default options.
3. At the console menu choose **1) Assign Interfaces**: WAN = `em0`, LAN = `em1`, optional interfaces `em2` (name it `DMZ` later) and `em3` (`MGMT`).
4. Choose **2) Set interface(s) IP address** and set each address from the [addressing plan](addressing-plan.md) (WAN `203.0.113.10/24` with no upstream gateway; LAN `10.10.10.1/24`; the others in the web interface).
5. From a VM in the LAN, open `https://10.10.10.1` and log in (the default account name is documented by Netgate; **change the default password immediately**).

Expected result: the dashboard shows four interfaces up with the addresses above.

## Step 3 - Interfaces

Interfaces > Assignments: add `em2` and `em3`, rename them `DMZ` and `MGMT`, enable them and set static IPv4 addresses `10.10.20.1/24` and `10.10.30.1/24`.
Interfaces > WAN: untick **Block bogon networks** (isolated lab only); leave **Block private networks** as is.

## Step 4 - Aliases, rules and NAT

1. Firewall > Aliases: create `RFC1918`, `MGMT_SSH_SOURCES`, `SIEM_PORTS` ([firewall-policy.md](firewall-policy.md)).
2. Firewall > NAT > Port Forward: add the SSH forward to `10.10.20.10:22` with *Add associated filter rule* ([nat-and-vlans.md](nat-and-vlans.md)).
3. Firewall > Rules: create the rules for LAN, DMZ and MGMT **in the order of the tables**; tick *Log* where the table says so.
4. Check Firewall > NAT > Outbound is on *Automatic outbound NAT*.

Expected result: rule lists identical to the tables; the WAN tab contains the associated SSH rule.

## Step 5 - The other machines

Install each VM, set the address from the plan, set the time zone to UTC, and:

| VM | Extra setup |
|---|---|
| web01 (Ubuntu) | Install `openssh-server`. Create the users from the scenario only if you want to repeat it. Install Filebeat or a Splunk Universal Forwarder later |
| WS01 (Windows) | Static address; optional Sysmon |
| kali01 | Static address `203.0.113.45/24`, gateway `203.0.113.10` |
| siem01 | Splunk or Elastic; allow the syslog port (below) |

Check basic reachability: from WS01 `ping 10.10.10.1` (expected: replies).

## Step 6 - Remote syslog to the SIEM

See [siem-integration.md](siem-integration.md). In short: Status > System Logs > Settings > tick *Send log messages to remote syslog server*, enter `10.10.30.50:5514`,
tick *Firewall Events* ([Netgate: remote logging](https://docs.netgate.com/pfsense/en/latest/monitoring/logs/remote.html)).

## Step 7 - Verify with the tests

On a machine of each zone (the script is a plain Bash script; it needs `nc` and `ping`):

```bash
./scripts/lab_connectivity_test.sh --zone LAN --confirm-lab     # on WS01 (use WSL, Git Bash or a Linux VM in the LAN)
./scripts/lab_connectivity_test.sh --zone DMZ --confirm-lab     # on web01
./scripts/lab_connectivity_test.sh --zone MGMT --confirm-lab    # on jump01 or siem01
./scripts/lab_connectivity_test.sh --zone WAN --confirm-lab     # on kali01
```

Each line prints `PASS` when the real result matches the expectation. Copy the results into `TEST_RESULTS.md`. A `FAIL` is not a bug in the script: it means the firewall
behaves differently from the design, so check the rules and the firewall log ([troubleshooting.md](troubleshooting.md)).

## Step 8 - Generate and read firewall events

1. From kali01, connect once to `203.0.113.10:22` (allowed, forwarded) and once to `203.0.113.10:80` (blocked).
2. In pfSense, Status > System Logs > Firewall: find both events and note the rule and interface of each.
3. Copy `/var/log/filter.log` (or the SIEM events) and run `filterlog_summary.sh` on it.
4. Capture the traffic with Diagnostics > Packet Capture (interface WAN, port 22) and open the file in Wireshark ([packet-analysis.md](packet-analysis.md)).

## Step 9 - Screenshots and record

Take the screenshots listed in [../screenshots/README.md](../screenshots/README.md) and fill in the "MANUAL VERIFICATION" table in `TEST_RESULTS.md`.
