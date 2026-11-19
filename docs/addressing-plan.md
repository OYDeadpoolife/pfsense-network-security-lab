# Addressing plan, routing and VLANs

## IP addresses

| Host | Zone | Address | Mask | Gateway | DNS | Assignment |
|---|---|---|---|---|---|---|
| pfsense-lab WAN (`em0`) | WAN | `203.0.113.10` | /24 | none (no upstream) | - | static |
| pfsense-lab LAN (`em1`) | LAN | `10.10.10.1` | /24 | - | - | static |
| pfsense-lab DMZ (`em2`) | DMZ | `10.10.20.1` | /24 | - | - | static |
| pfsense-lab MGMT (`em3`) | MGMT | `10.10.30.1` | /24 | - | - | static |
| kali01 | WAN | `203.0.113.45` | /24 | `203.0.113.10` | - | static |
| WS01 | LAN | `10.10.10.20` | /24 | `10.10.10.1` | `10.10.10.1` | static or DHCP reservation |
| web01 | DMZ | `10.10.20.10` | /24 | `10.10.20.1` | `10.10.20.1` | static |
| siem01 | MGMT | `10.10.30.50` | /24 | `10.10.30.1` | `10.10.30.1` | static |
| jump01 | MGMT | `10.10.30.5` | /24 | `10.10.30.1` | `10.10.30.1` | static |
| backup01 | MGMT | `10.10.30.40` | /24 | `10.10.30.1` | `10.10.30.1` | static |
| scanner01 | MGMT | `10.10.30.60` | /24 | `10.10.30.1` | `10.10.30.1` | static |

All private ranges are RFC 1918 (`10.10.0.0/16` is used by this lab). The `/24` subnets leave room to grow. They were chosen to avoid the
`192.168.x.x` range that most home routers use, so the lab cannot clash with your real network even if a cable is connected by mistake.

## Routing

* pfSense is the **only router**. Each zone has a *connected route* through its own interface; no static routes are needed.
* The hosts use pfSense as their **default gateway**. Traffic between zones therefore always passes the firewall.
* The WAN has **no upstream gateway** because the lab is isolated. (pfSense accepts a WAN without a gateway; if its wizard insists on one,
  enter `203.0.113.10` itself or leave it blank in the console setup.) If you want the VMs to reach the real Internet for updates, add a *separate* NAT
  adapter to those VMs temporarily, or use a snapshot taken before the update, rather than connecting the lab's WAN to your home network.
* Return traffic needs no route: `pf` is stateful and remembers every allowed connection.

## NAT summary

| Type | Rule | Effect |
|---|---|---|
| Outbound NAT (automatic) | LAN, DMZ and MGMT to WAN | Inside hosts appear as `203.0.113.10` on the WAN |
| Port forward (destination NAT) | WAN `203.0.113.10:22` to `10.10.20.10:22` | The Internet can reach SSH on web01 |

Details in [nat-and-vlans.md](nat-and-vlans.md).

## VLAN plan (optional exercise)

| VLAN ID | Name | Subnet | pfSense interface (tagged) |
|---|---|---|---|
| 10 | LAN | `10.10.10.0/24` | `em1.10` |
| 20 | DMZ | `10.10.20.0/24` | `em1.20` |
| 30 | MGMT | `10.10.30.0/24` | `em1.30` |

In the VLAN exercise the three inside zones share **one** trunk adapter on pfSense and are separated by 802.1Q tags instead of by separate
virtual networks. The addresses stay the same. See [nat-and-vlans.md](nat-and-vlans.md) for the steps and for the hypervisor caveat.

## DHCP and DNS

* Servers use static addresses. WS01 may use DHCP from pfSense on `em1` with a reservation for `10.10.10.20`.
* DNS: the pfSense DNS Resolver answers queries from the zones that are allowed to ask it (LAN rule 1). It has no Internet upstream in the isolated lab,
  so only lab names resolve. Add static entries (Services > DNS Resolver > Host Overrides) for the lab hosts if you want names.
* Time: set the same time zone (UTC) on all machines. Log analysis across hosts depends on consistent clocks.
