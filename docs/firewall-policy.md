# Firewall policy

> **Status:** a design. It has **not** been applied to a real pfSense by the author. `samples/lab-expectations.csv` turns each line of this
> policy into a test you can run (see [connectivity-tests.md](connectivity-tests.md)).

## How pfSense evaluates rules

* Rules are attached to the **interface where the traffic enters** (ingress). Rules on the LAN tab control traffic coming *from* the LAN.
* Rules are checked **top to bottom; the first match wins**. Order therefore matters.
* If nothing matches, the **default deny** applies: the packet is dropped silently (no reply) and, by default, logged.
* The firewall is **stateful**: once a connection is allowed, its replies are allowed automatically and are not logged again.
* A **port forward rewrites the destination before the rules are checked**, so the WAN rule must allow the *inside* address and port
  (the log shows `10.10.20.10`, not the WAN address). With the default "Add associated filter rule" option pfSense creates that rule for you.

## Aliases (Firewall > Aliases)

| Alias | Type | Content | Used for |
|---|---|---|---|
| `RFC1918` | Network(s) | `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` | "Not private" = the Internet |
| `MGMT_SSH_SOURCES` | Host(s) | `10.10.30.5`, `10.10.30.40`, `10.10.30.60` | Who may SSH to the DMZ |
| `SIEM_PORTS` | Port(s) | `5044`, `9997` | Log shipping to the SIEM |

## Rules per interface (in this order)

### WAN (`em0`) - traffic from the simulated Internet

| # | Action | Proto | Source | Destination | Port | Log | Purpose |
|---|---|---|---|---|---|---|---|
| 1 | Pass | TCP | any | `10.10.20.10` (after NAT) | 22 | yes | Associated rule of the port forward: SSH to web01 |
| - | **Block** | any | any | any | any | yes | Default deny: everything else, including the web interface of pfSense itself |

Interface options on the WAN: leave **Block private networks and loopback addresses** enabled if your WAN uses public addresses; in this lab the WAN uses
a documentation range, which is not private. **Block bogon networks** blocks addresses that should never appear on the Internet, and the documentation range
may be on that list: in this isolated lab, untick it on the WAN, and **re-enable it in any real deployment**
([Netgate: block private and bogon networks](https://docs.netgate.com/pfsense/en/latest/firewall/rule-methodology.html)).

### LAN (`em1`) - traffic from workstations

| # | Action | Proto | Source | Destination | Port | Log | Purpose |
|---|---|---|---|---|---|---|---|
| 1 | Pass | TCP/UDP | LAN net | This firewall (LAN address) | 53 | no | DNS to the resolver |
| 2 | Pass | ICMP echo | LAN net | any | - | no | Ping for testing |
| 3 | **Block** | any | LAN net | MGMT net | any | **yes** | Workstations must not reach the SIEM or jump host |
| 4 | Pass | TCP | LAN net | DMZ net | 80, 443 | no | Browse the DMZ web server |
| 5 | Pass | TCP | LAN net | not `RFC1918` | 80, 443 | **yes** | Web egress to "the Internet" |
| - | **Block** | any | any | any | any | yes | Default deny |

The anti-lockout rule (pfSense's built-in access to its web interface from the LAN) stays enabled.

### DMZ (`em2`) - traffic from the servers

| # | Action | Proto | Source | Destination | Port | Log | Purpose |
|---|---|---|---|---|---|---|---|
| 1 | **Block** | any | DMZ net | LAN net | any | **yes** | A compromised server must not reach the workstations |
| 2 | Pass | TCP | `10.10.20.10` | `10.10.30.50` | `SIEM_PORTS` | no | Log shipping to the SIEM |
| - | **Block** | any | any | any | any | yes | Default deny (no web egress from the DMZ in this lab: add one only if you need package updates) |

### MGMT (`em3`) - traffic from the management zone

| # | Action | Proto | Source | Destination | Port | Log | Purpose |
|---|---|---|---|---|---|---|---|
| 1 | Pass | TCP | `MGMT_SSH_SOURCES` | DMZ net | 22 | no | Administration, backups and scanning of the DMZ over SSH |
| 2 | Pass | any | MGMT net | any | any | no | Simplification: management may reach everything (tighten in a real deployment) |
| - | **Block** | any | any | any | any | yes | Default deny |

The two syslog streams from pfSense to the SIEM originate on the firewall itself and need no interface rule.

## Logging

Status > System Logs > Settings: keep **Log packets matched from the default block rules in the ruleset** enabled (it is by default, which is why the
scanner's packets appear in the log). Enable **Log** only on the rules marked above; logging every allowed packet fills the log quickly.

## What the design should produce

| Test | Expected | Log evidence |
|---|---|---|
| Internet host probes ports 23, 445, 3389 on the WAN address | Dropped | `block` on `em0`, default deny rule, tracker `1000000103` |
| Internet host connects to WAN port 22 | Allowed, reaches web01 | `pass` on `em0`, destination `10.10.20.10:22` |
| web01 connects to WS01 on 445 or 3389 | Dropped | `block` on `em2`, DMZ rule 1 |
| WS01 connects to the SIEM on 8000 | Dropped | `block` on `em1`, LAN rule 3 |
| WS01 connects to an Internet address on 443 | Allowed | `pass` on `em1`, LAN rule 5 |
| jump01 connects to web01 on 22 | Allowed | `pass` on `em3`, MGMT rule 1 |

`samples/filterlog_sample.log` contains exactly these cases.

## Review of the policy (what a reviewer would question)

* The SSH port forward accepts connections from **any** Internet address. That is intentional for the lab, and a real server would restrict the sources or use keys only.
* `MGMT -> any` is broad. In production, list the allowed flows.
* There is no IPv6 policy: the lab disables IPv6 on the VMs.
* Egress from the DMZ is denied by default; this blocks updates, which is a usability cost of a safer design.
