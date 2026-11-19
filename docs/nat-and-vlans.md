# NAT and VLANs

> **Status:** explanation and instructions. Menu paths for port forwards come from Netgate's documentation
> ([Port Forwards](https://docs.netgate.com/pfsense/en/latest/nat/port-forwards.html)); the VLAN steps are from general knowledge of pfSense and **have not been run by the author**.

## NAT in one page

**NAT (Network Address Translation)** rewrites addresses in packets as they pass the firewall.

| Kind | What it rewrites | In this lab |
|---|---|---|
| **Outbound NAT / masquerading** (source NAT) | The *source* of traffic leaving a private network | Inside hosts (`10.10.x.x`) appear as `203.0.113.10` on the WAN. pfSense creates these rules automatically (Firewall > NAT > Outbound, "Automatic outbound NAT") |
| **Port forward** (destination NAT) | The *destination* of traffic arriving from outside | WAN `203.0.113.10:22` is rewritten to `10.10.20.10:22` |
| **1:1 NAT** | A whole address maps to another | Not used |

### Creating the port forward (Firewall > NAT > Port Forward > Add)

| Field | Value |
|---|---|
| Interface | WAN |
| Protocol | TCP |
| Destination | **WAN address** |
| Destination port range | SSH (22) |
| Redirect target IP | `10.10.20.10` |
| Redirect target port | SSH (22) |
| Description | NAT: SSH to web01 |
| Filter rule association | **Add associated filter rule** (the default) |

> *"A port forwarding rule only defines which packets the firewall will redirect, a firewall rule allows those packets to pass."*
> The associated rule appears under Firewall > Rules > WAN. Without it, the forwarded packets are dropped. (Netgate documentation.)

### What this looks like in the log

`pf` translates the destination **before** the rules are checked, so the logged destination is the inside address:

```text
Mar 14 10:02:10 pfsense-lab filterlog[84921]: 98,,,1710410101,em0,match,pass,in,4,0x0,,64,16967,0,DF,6,tcp,60,203.0.113.45,10.10.20.10,57496,22,0,S,4186635331,,64240,,mss;sackOK;TS;nop;wscale
```

An analyst who searches the firewall log for the WAN address `203.0.113.10` will **not** find the forwarded connections. Search for the inside address and port, or
for the rule's tracker ID.

### NAT reflection

By default, hosts *inside* cannot reach a port-forwarded service by its WAN address. NAT reflection can change that; it is not needed here, because WS01 reaches web01
directly by `10.10.20.10`.

## VLANs in one page

A **VLAN** splits one physical (or virtual) network into several separate broadcast domains using an **802.1Q tag** (a 12-bit VLAN ID) inside the Ethernet frame.
A **trunk** link carries several tagged VLANs; an **access** link carries one untagged VLAN. The router (pfSense) needs one **sub-interface per VLAN** to route between them.

### Option 1 (default for this lab): separate virtual networks

Each zone has its own virtual network and its own pfSense adapter (`em1`, `em2`, `em3`). It needs no tagging and works on every hypervisor.

### Option 2 (exercise): VLANs on a trunk

> **Caveat:** whether tagged frames pass between virtual machines depends on the hypervisor's virtual switch. **This has not been verified.** If it does not work on
> your VMware or UTM setup, use Option 1.

1. Give pfSense **one** inside adapter (for example `em1`) on a virtual network that passes tagged frames, and connect the inside VMs to the same network.
2. **Interfaces > Assignments > VLANs > Add**: parent interface `em1`, VLAN tag `10`; repeat for tags `20` and `30`.
3. **Interfaces > Assignments**: add the new VLAN interfaces and rename them `LAN`, `DMZ`, `MGMT`; enable them and set the static addresses from the
   addressing plan (`10.10.10.1/24`, `10.10.20.1/24`, `10.10.30.1/24`).
4. Re-create the firewall rules on the new interface tabs (the rules in `firewall-policy.md` do not change).
5. On a Linux VM, create a tagged sub-interface to test it. This changes network settings on that VM only:

   ```bash
   sudo ip link add link ens33 name ens33.20 type vlan id 20      # a tagged interface for VLAN 20 on adapter ens33
   sudo ip addr add 10.10.20.10/24 dev ens33.20                    # give it the DMZ address
   sudo ip link set ens33.20 up                                     # bring it up; "ip -d link show ens33.20" shows "vlan id 20"
   ```

   Adapter names differ (`ens33`, `eth0`, ...). These commands do not persist after a reboot.

### What to observe

A packet capture on the trunk shows the tag: in Wireshark, filter `vlan.id == 20`. If the VLAN does not work, the usual causes are a switch that strips
tags, a missing tagged interface on the host, or the wrong parent interface (see the troubleshooting guide).
