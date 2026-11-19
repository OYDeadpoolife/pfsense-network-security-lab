# Reading the firewall log

The examples use `samples/filterlog_sample.log`, a **synthetic** log built to the documented format. It is not a capture from a real firewall.

## Where the log comes from

* On pfSense: Status > System Logs > Firewall (a friendly view), or the raw file `/var/log/filter.log`. The raw line is what a SIEM receives.
* Each line is `time host filterlog[pid]: <comma separated values>`. Remote syslog adds a priority prefix such as `<134>` (see [siem-integration.md](siem-integration.md)).

## The line, field by field

The field order is the one in Netgate's [Raw Filter Log Format](https://docs.netgate.com/pfsense/en/latest/monitoring/logs/raw-filter-format.html).

```text
Mar 14 10:06:40 pfsense-lab filterlog[84921]: 98,,,1710410101,em0,match,pass,in,4,0x0,,64,3478,0,DF,6,tcp,60,203.0.113.45,10.10.20.10,52368,22,0,S,2120498488,,64240,,mss;sackOK;TS;nop;wscale
```

| # | Value | Field | Meaning |
|---|---|---|---|
| 1 | `98` | rule number | Position of the rule in the pf ruleset |
| 2 | (empty) | sub-rule | Rarely used |
| 3 | (empty) | anchor | Rule group, usually empty |
| 4 | `1710410101` | **tracker** | Unique ID of the rule: the stable way to identify it (`1000000103` is the built-in default deny) |
| 5 | `em0` | interface | The real NIC: here the WAN |
| 6 | `match` | reason | Why it was logged |
| 7 | `pass` | **action** | `pass` or `block` |
| 8 | `in` | direction | Direction relative to the interface |
| 9 | `4` | IP version | 4 or 6 |
| 10-17 | `0x0,,64,3478,0,DF,6,tcp` | IPv4 header | TOS, ECN, TTL (`64`), IP ID, fragment offset, flags (`DF`), protocol number (`6`), protocol name |
| 18 | `60` | length | Packet length in bytes |
| 19 | `203.0.113.45` | **source** | |
| 20 | `10.10.20.10` | **destination** | After NAT: the inside address |
| 21 | `52368` | source port | |
| 22 | `22` | **destination port** | |
| 23 | `0` | data length | A SYN carries no data |
| 24 | `S` | TCP flags | `S` = SYN: this is the *start of a connection* |
| 25-29 | | sequence, ack, window, urgent, options | |

UDP lines end after `source port, destination port, data length`. ICMP echo lines end with `request,<id>,<sequence>`.

**TTL as a clue:** the TTL shows the sender's operating system and distance: about 64 for Linux, 128 for Windows (minus the hops). A scanner arriving with 52 has crossed
about 12 routers.

## Allowed versus blocked: what to look for

| Question | Look at |
|---|---|
| Was it allowed? | field 7: `pass` or `block` |
| Why? Which rule? | fields 1 and 4 (rule number and tracker). Map the tracker to a rule description in the pfSense GUI |
| Where did it enter? | field 5 (interface) |
| Who started it? | source and destination (fields 19-20), and the TCP flags `S` |
| Is it one event or a pattern? | count by source, destination port or rule |

A **passed** connection is logged **once** (the SYN); the replies belong to the state and are not logged. A **blocked** connection is logged for every packet that arrives, so a
client that retries produces several lines with the same source port and sequence number, as in the sample (`10.10.20.10:43455 -> 10.10.10.20:445`).

## The summary script

```bash
./scripts/filterlog_summary.sh --input samples/filterlog_sample.log
./scripts/filterlog_summary.sh --input samples/filterlog_sample.log --format csv > events.csv    # one row per event, for a spreadsheet or SIEM
./scripts/filterlog_summary.sh --input samples/filterlog_sample.log --ip 10.10.20.10             # only events involving web01
```

It reads standard BSD syslog lines and RFC 5424 lines, and counts lines that are not firewall events instead of failing. Real output on the sample:

```text
Allowed connections to non-private destinations (what internal hosts reached on the Internet)
       9  10.10.10.20 -> 203.0.113.45:443
       2  10.10.10.20 -> 198.51.100.80:443
       1  10.10.10.20 -> 198.51.100.90:443
       1  10.10.10.20 -> 198.51.100.81:443

Rule hits (rule number, tracker ID, action)
      60  rule 98   tracker 1710410101   pass
      14  rule 12   tracker 1000000103   block
      13  rule 65   tracker 1710410205   pass
      11  rule 81   tracker 1710410401   pass
       6  rule 71   tracker 1710410301   block
```

## What the sample log shows (the story)

| Time (UTC) | Event | Reading |
|---|---|---|
| 09:12:03-09:12:22 | 14 `block` lines on `em0` from `198.51.100.23` to `203.0.113.10`, ports 23, 445, 3389, 8080, 5900, 3306, 1433, 21, 25, 110; some repeated one second later | A port scan. The default deny rule drops it. The same source never gets an answer: scanners usually move on |
| 09:30:10-09:30:19 | 3 `block` lines on `em1`: `10.10.10.20` to `10.10.30.50:8000`, same source port, same sequence number | A user trying the SIEM web interface from the LAN: blocked by LAN rule 3. The same port and sequence number with growing time gaps (0, 3, 9 s) are TCP retransmissions: the client keeps trying. Benign, but a policy question |
| 10:02:10-10:06:40 | 60 `pass` lines on `em0` from `203.0.113.45` to `10.10.20.10:22` (rule 98) | An Internet host opens 60 SSH connections in under five minutes: brute force. The destination is the *inside* address because of the port forward |
| 10:15:02-10:15:23 | 6 `block` lines on `em2`: `10.10.20.10` to `10.10.10.20` ports 445 and 3389 | The DMZ server trying to reach a workstation: blocked by DMZ rule 1. A server that suddenly makes new internal connections is a strong sign that it has been compromised |
| 11:30:15 | `pass` on `em1`: `10.10.10.20:63981` to `203.0.113.45:443` (rule 65) | The workstation reaches the same Internet address that attacked web01 |
| 11:31-11:38 | 8 more `pass` lines to `203.0.113.45:443` about one per minute | A beacon: regular outbound connections |

### Correlating one connection across the logs

The source port identifies a TCP connection. This SSH connection appears in three places:

| Source | Line |
|---|---|
| Firewall (`filter.log`) | `Mar 14 10:06:40 ... 203.0.113.45,10.10.20.10,52368,22,0,S,...` |
| web01 (`auth.log`) | `Mar 14 10:06:41 web01 sshd[3367]: Accepted password for svc-backup from 203.0.113.45 port 52368 ssh2` |

The firewall sees the SYN about a second before sshd logs the login. The firewall shows the connection was **allowed and who started it**; the server shows **what happened inside it**.
The Windows connections correlate the same way with Sysmon event 3 (source port `63981` in the Sysmon data of the SOC lab project).

## Limits of firewall logs

* They show **metadata** (who talked to whom, when, allowed or not), not content. A `pass` on port 443 does not say what was sent.
* A passed connection appears **once**: you cannot tell its duration or volume from the log.
* They show the *firewall's* view: traffic that never crosses it (inside one zone) is invisible.
* Only rules with logging enabled (and the default deny) create lines: a missing line does not prove nothing happened.
