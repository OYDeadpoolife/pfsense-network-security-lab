# Test results — pfsense-network-security-lab

Last full local run: **2026-10-03**. Result: **141 passed, 0 failed, 0 skipped** (`python3 -m pytest`, about 1 second).
GitHub Actions: **2026-11-19**. Result: **141 passed** on Ubuntu and on macOS. The first run failed; see "FAIL" below.
After `docs/glossary.md` was added the suite has **143 passed** (the two new tests are the existence and link checks of that page; local run, 2026-11-19).

> **The most important sentence on this page:** *no pfSense virtual machine was built or configured, so none of the firewall configuration (rules, NAT, VLANs,
> remote syslog) has been tested on a real firewall.* The tests verify the sample files, the two scripts, the file formats and the documents. The VM-based lab
> results are blank on purpose: they must be recorded by whoever builds the lab.

## Environment of that run

| Item | Value |
|---|---|
| Operating system | macOS 15.7.4 (arm64), Bash 3.2.57, awk 20200816 |
| Python / pytest | Python 3.9.6, pytest 8.4.2 |
| ShellCheck / shfmt | ShellCheck 0.11.0, shfmt 3.14.1 |
| tcpdump | the version that ships with macOS (used by one test and for the real output in `docs/packet-analysis.md`) |

## PASS — executed and successful

| Area | Tests | What was verified |
|---|---|---|
| Sample generators (`test_generators.py`) | 13 | Firewall log and capture are **byte-for-byte reproducible**; every log line has the documented field layout and count; time order; 95 `pass` and 23 `block`; only documentation and private addresses; every (rule, tracker, interface, action) comes from the rule table; the default deny uses pfSense's tracker `1000000103`; the scenario events are present (scan blocked, 60 SSH connections to the *translated* address `10.10.20.10`, 6 DMZ-to-LAN blocks, 9 connections to `203.0.113.45:443`); **source ports agree with the SOC-lab SSH and Sysmon data**; TCP retransmissions repeat port and sequence number |
| Summary script (`test_filterlog_summary.py`) | 19 | The numbers in the text summary; **the CSV output equals an independent Python parser** on all 118 events; `--ip` pivot; `--top`; standard input; a missing final newline; RFC 5424 lines, IPv6 lines and junk are counted, not fatal; empty and CRLF files; paths with spaces and Hebrew characters in two locales; a file named like an awk assignment (`x=1`); error exit statuses; the input file is never modified; the temporary directory is removed |
| Connectivity script (`test_connectivity.py`) | 21 | Help, version, option errors; `--dry-run` and `--list` send nothing; **refuses to send without `--confirm-lab`**; **refuses any target outside `10.10.0.0/16` and `203.0.113.0/24`** (tested with 7 forbidden addresses, before any traffic); loopback only with an explicit flag; PASS/FAIL logic and exit status against a **local listener**; ICMP to loopback; invalid rows; only the requested zone runs; the 15 committed tests are inside the lab and **match the table in the documentation** |
| Packet capture (`test_pcap.py`) | 7 | Valid pcap structure (15 packets); **every IP and TCP checksum is correct** (computed independently and confirmed by `tcpdump`); the numbers quoted in `docs/packet-analysis.md` (6 scanner packets, 7 SYNs, 1 SYN-ACK, 9 packets on port 22, 2 banners, 4 conversations); the blocked scanner gets no answer; the SSH connection is complete; **the capture matches the firewall log** (same source port, same time) |
| SIEM files (`test_siem.py`) | 7 | The Splunk `rex` regular expression (converted to Python syntax) extracts every field of **all 118 log lines** and agrees with the independent parser; it also matches the remote-syslog form with a `<134>` prefix; the searches are read-only and marked NOT TESTED; the expected numbers in the search comments equal the sample; the Logstash column order follows the documented field order; no secrets in the examples |
| Documents (`test_docs.py`) | 45 (43 on 2026-10-03, plus the glossary) | Required documents exist; **all relative links resolve**; code fences are balanced; Mermaid diagrams are well formed; numbers in the README match the samples; the status banners are present; no document claims a real pfSense run; both paths are offered; the screenshot guide covers the README placeholders and no screenshot is committed |
| Repository (`test_static.py`) | 31 | Required files; scripts executable; no `sudo`/installs/`eval`; the only deleting command removes the script's own temporary directory; no secrets or personal data; **only the synthetic capture is committed**; ShellCheck clean; shfmt clean |

### GitHub Actions (2026-11-19)

Commit `7e0c5cc`, run: <https://github.com/OYDeadpoolife/pfsense-network-security-lab/actions/runs/44528251017>. **141 passed in both jobs**
(`ubuntu-latest` and `macos-latest`, Python 3.12). This was the first run of the scripts and tests on Linux.

### Mutation check (does the suite really catch bugs?)

Five deliberate bugs were introduced one at a time into a copy of the project, and the suite failed each time: a wrong awk field for the destination address,
the lab-only target guard removed, the `--confirm-lab` requirement removed, an expectation flipped in the CSV, and a broken checksum in the capture generator.

### Development notes (nothing hidden)

During development the suite failed three times before the final run, every time because of wrong expectations in my own tests: a link checker that also looked inside inline-code
examples, a line count that did not account for how the test input ended, and an honesty check that did not allow for a sentence wrapped over two lines. They were corrected in the tests. Separately, a self-review corrected one
statement in the documentation (the time range of the DMZ block events) and the capture generator was changed so that its SSH connection uses the same source port and time as
the firewall log and the Linux log.

## FAIL — executed and failed

None in the last local run. **The first GitHub Actions run (2026-11-19, commit `ccceb13`) failed in both jobs with one failing test and 140 passing.**
`test_no_backup_or_cache_files` counted `.pyc` files that the test run itself writes under `__pycache__` (they are git-ignored and never published).
This had not shown up locally, where no bytecode was written. The test now ignores `__pycache__` and `.pytest_cache`. Fixed in commit `7e0c5cc`; both jobs have been green since.

## NOT TESTED — environment not available to the author when this was written

| Item | Why |
|---|---|
| **The whole pfSense configuration**: interfaces, aliases, rules, NAT, outbound NAT, bogon/private options | No pfSense VM was built |
| **The expected results of the 15 connectivity tests on a real lab** (`samples/lab-expectations.csv`) | They are predictions from the design |
| VLAN configuration (Option 2) | Needs a hypervisor that passes 802.1Q tags |
| Remote syslog from pfSense to a SIEM | No pfSense, no SIEM |
| Splunk searches, Logstash and Filebeat configuration | No Splunk/Elastic; only the regular expression was tested |
| The synthetic capture **in Wireshark** | Wireshark was not installed; only `tcpdump` and a Python parser were used. The statements about Wireshark's own flags (for example retransmission marking) are expectations |
| Whether the documentation-range `203.0.113.0/24` is blocked by pfSense's bogon list | Not verifiable without pfSense; the setup guide tells you to untick the option in the lab and why |
| Linux on a real machine or VM | Only the Ubuntu GitHub Actions runner was used (see the CI section above) |
| Mermaid rendering on GitHub | Only the syntax balance is checked |

## MANUAL VERIFICATION REQUIRED — to be done by whoever builds the lab (Path B)

Record the real outcome in the tables below (PASS, or FAIL with what you saw). Do not fill them in unless you ran the step.

| Step | How | Result (fill in) | Date |
|---|---|---|---|
| Virtual networks and VMs created | `docs/setup-guide.md` steps 1-5 | | |
| Interfaces and addresses as in the plan | pfSense dashboard | | |
| LAN tests T01-T06 | `scripts/lab_connectivity_test.sh --zone LAN --confirm-lab` on WS01 or a LAN VM | | |
| DMZ tests T10-T13 | same, `--zone DMZ`, on web01 | | |
| MGMT tests T20-T21 | same, `--zone MGMT` | | |
| WAN tests T30-T32 | same, `--zone WAN`, on kali01 | | |
| Allowed and blocked events in the firewall log | Status > System Logs > Firewall | | |
| Remote syslog reaches the SIEM | `docs/siem-integration.md` verification table | | |
| Packet capture opens and shows the expected patterns | Wireshark with the synthetic file, then your own capture | | |
| Screenshots taken | `screenshots/README.md` | | |

Until the VM-based rows are filled in, describe this project as: *"a pfSense lab design with a synthetic, format-faithful firewall log and capture, working analysis and
test scripts, and documentation; the firewall configuration itself has not yet been built and verified."*
