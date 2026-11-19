# Safe connectivity tests

`samples/lab-expectations.csv` lists 15 tests, one per firewall behaviour, and the result the design predicts. `scripts/lab_connectivity_test.sh` runs the tests of one zone.

> **The expected results are predictions from the firewall design.** They were **not** confirmed on a real pfSense. The script itself is tested
> (against a local listener), and its safety checks are tested.

## Safety properties of the script

* It is **not a scanner**: it makes one connection (or one ping) per test line, to a single address and port, one after the other.
* It contacts **only** `10.10.0.0/16` and `203.0.113.0/24`, and aborts the whole run before sending anything if any line names another address.
* It refuses to send anything without `--confirm-lab`; `--dry-run` and `--list` show the tests without sending traffic.
* It never changes any configuration and needs no root privileges.

## The tests and the expected results

| ID | Run on (zone) | Test | Expected | Because |
|---|---|---|---|---|
| T01 | LAN | WS01 pings `10.10.10.1` | allow | LAN rule 2 |
| T02 | LAN | WS01 connects to `10.10.10.1:53` (TCP) | allow | LAN rule 1 |
| T03 | LAN | WS01 connects to `10.10.20.10:80` | allow | LAN rule 4 |
| T04 | LAN | WS01 connects to `10.10.20.10:22` | **block** | no rule: default deny |
| T05 | LAN | WS01 connects to `10.10.30.50:8000` | **block** | LAN rule 3 |
| T06 | LAN | WS01 connects to `203.0.113.45:443` | allow | LAN rule 5 |
| T10 | DMZ | web01 connects to `10.10.10.20:445` | **block** | DMZ rule 1 |
| T11 | DMZ | web01 connects to `10.10.10.20:3389` | **block** | DMZ rule 1 |
| T12 | DMZ | web01 connects to `10.10.30.50:5044` | allow | DMZ rule 2 |
| T13 | DMZ | web01 connects to `10.10.30.5:22` | **block** | no rule: default deny |
| T20 | MGMT | jump01 connects to `10.10.20.10:22` | allow | MGMT rule 1 |
| T21 | MGMT | jump01 connects to `10.10.30.1:443` | allow | MGMT rule 2 |
| T30 | WAN | kali01 connects to `203.0.113.10:22` | allow | port forward and its WAN rule |
| T31 | WAN | kali01 connects to `203.0.113.10:80` | **block** | default deny |
| T32 | WAN | kali01 connects to `203.0.113.10:443` | **block** | default deny (the GUI is not exposed) |

Several tests need something to **listen** on the target: for example port 80 on web01 (T03), port 443 on kali01 (T06), port 22 on web01 (T20, T30), port 5044 on siem01 (T12) and
port 8000 on siem01 (T05). Tests that expect **allow** will fail if nothing listens, even though the firewall is correct. Start a temporary listener on the target for the test:

```bash
python3 -m http.server 80 --bind 10.10.20.10        # on web01; needs root for port 80, so use "sudo" or pick a port above 1024 for the exercise
nc -l 5044                                           # on siem01 (syntax varies between netcat versions: "nc -l -p 5044" on some)
```

Stop the listener afterwards with Ctrl+C.

## How to read the output

```text
PASS T10  tcp 10.10.10.20:445  expected=block actual=block
FAIL T12  tcp 10.10.30.50:5044  expected=allow actual=block
```

* `PASS` means the observed result equals the design. `FAIL` means they differ.
* "block" means *no connection could be made within the timeout*. The script cannot tell a firewall drop from a closed port or a stopped service. **Always
  confirm the reason in the firewall log**: a real block appears as a `block` line (see [log-analysis.md](log-analysis.md)).
* Exit status: `0` all tests matched, `1` at least one did not, `2` invalid options or a forbidden target, `3` input problem.

## Self-test of the script (no lab needed)

The repository's own tests start a local listener and run the script against `127.0.0.1` with `--allow-loopback`, checking that an open port is reported as `allow`, a closed port as
`block` and a wrong expectation as `FAIL`. That proves the script's logic, not your firewall.
