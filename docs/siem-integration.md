# Sending the firewall log to a SIEM

> **Status:** instructions. The pfSense settings come from Netgate's documentation
> ([Remote Logging with Syslog](https://docs.netgate.com/pfsense/en/latest/monitoring/logs/remote.html)). **Nothing here has been tested against a real SIEM.** The extraction regular expression is
> tested in Python against the sample log (`tests/test_siem.py`); the Splunk, Logstash and Filebeat configuration is not.

## On pfSense

Status > System Logs > **Settings**:

| Setting | Value | Notes |
|---|---|---|
| Send log messages to remote syslog server | ticked | |
| Remote log servers | `10.10.30.50:5514` | Up to three servers, `address:port`; the default port is 514 |
| Remote Syslog Contents | **Firewall Events** (or Everything) | Choose only what you need |
| Source Address / IP Protocol | defaults | |

Facts to know:

* **pfSense's own syslog daemon sends over UDP only.** For TCP use the `syslog-ng` package (Netgate documentation). UDP is not reliable: messages can be lost without notice.
* Port 514 needs administrator rights on the receiving Linux machine; use a high port such as `5514` for the lab.
* The format is BSD syslog (RFC 3164) by default; the *Log Message Format* option can switch to RFC 5424. `filterlog_summary.sh` and the regular expression below handle both.
* The firewall needs no rule to send its own logs. The **receiving** side must allow UDP `5514` from `10.10.30.1` (a host firewall on siem01, if any).

A remote message looks like this (the PRI `<134>` = facility local0, severity info is added at the front):

```text
<134>Mar 14 10:06:40 pfsense-lab filterlog[84921]: 98,,,1710410101,em0,match,pass,in,4,0x0,,64,3478,0,DF,6,tcp,60,203.0.113.45,10.10.20.10,52368,22,0,S,2120498488,,64240,,mss;sackOK;TS;nop;wscale
```

## Splunk (NOT TESTED)

1. Settings > Data inputs > **UDP** > New: port `5514`, source type `pfsense:filterlog`, index `soc_lab`.
2. Extract the fields at search time with `siem/splunk_filterlog.spl` (one `rex` that reads the CSV), or build a field extraction.
3. Example searches (all in that file): blocked traffic by source, allowed connections to external addresses, a pivot on one address.

## Elastic (NOT TESTED)

Option 1, **Elastic Agent**: add the *pfSense* integration and follow its instructions (check its current documentation).

Option 2, **Filebeat** (`siem/filebeat-syslog.yml.example`): a `syslog` input on UDP `5514`, then parse the CSV with an ingest pipeline or Logstash.

Option 3, **Logstash** (`siem/logstash-pfsense.conf.example`): a `syslog`/`udp` input and a `csv` filter that names the fields in the documented order.

## Verify end to end

| Check | Command or action | Expected |
|---|---|---|
| pfSense is sending | On siem01: `sudo tcpdump -i any -nn udp port 5514` | Packets from `10.10.30.1` when you generate traffic |
| The SIEM stored them | Search `index=soc_lab sourcetype=pfsense:filterlog` (Splunk) | Events appear within seconds |
| Fields are right | Compare one event with the table in `log-analysis.md` | action, source, destination and ports match |
| Time is right | Compare with the pfSense GUI | Same minute; no multi-hour offset |

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| No packets arrive on the SIEM | Remote logging not enabled; wrong address or port; host firewall on siem01 | Re-check the settings; `tcpdump` on siem01; allow UDP 5514 |
| Packets arrive, nothing in the SIEM | The input listens on a different port or has the wrong source type | Check the Data input; look at the SIEM's internal logs |
| Events have the wrong time | Time zone or year missing (BSD syslog has neither) | Set the time zone on the input or use RFC 5424 timestamps |
| Only some events arrive | UDP loss, or rule logging is off | Use `syslog-ng` with TCP; enable *Log* on the rules |
| Fields are shifted | IPv6 lines or ICMP lines have a different layout | Parse by protocol, as `scripts/filterlog.awk` does |
