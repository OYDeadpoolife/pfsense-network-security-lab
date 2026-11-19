# filterlog.awk - turn pfSense "filterlog" lines into tab-separated events.
#
# Input (stdin): firewall log lines from /var/log/filter.log or from a remote syslog server, in either
#                  BSD syslog format   "Mar 14 09:12:03 pfsense-lab filterlog[84921]: <csv>"
#                  or RFC 5424 format  "<134>1 2026-03-14T09:12:03+00:00 pfsense-lab filterlog 84921 - - <csv>"
# Output (stdout): time, host, rule, tracker, interface, action, direction, ip_version, protocol,
#                  src_ip, src_port, dst_ip, dst_port, detail   (tab separated; "-" when not applicable)
#                  "detail" is the TCP flags (S, SA, ...) or the ICMP type.
# Output (stderr): STAT<TAB>name<TAB>value rows.
#
# Variable passed with -v:  ip   keep only events whose source or destination equals this address
#
# The field order is the one documented by Netgate ("Raw Filter Log Format"):
#   rule,sub-rule,anchor,tracker,interface,reason,action,direction,ip-version, then
#   IPv4: tos,ecn,ttl,id,offset,flags,protocol-id,protocol-text,length,src,dst, then TCP/UDP/ICMP data
#   IPv6: class,flow-label,hop-limit,protocol-text,protocol-id,length,src,dst, then TCP/UDP/ICMP data
# Only portable awk features are used (BWK awk, mawk and gawk).

BEGIN {
    OFS = "\t"
}

{
    total++
    line = $0
    # Find the part after "filterlog" in either syslog flavour.
    if (match(line, /filterlog(\[[0-9]+\])?: /)) {
        csv = substr(line, RSTART + RLENGTH)
    } else if (match(line, /filterlog [0-9]+ [^ ]+ [^ ]+ /)) {
        csv = substr(line, RSTART + RLENGTH)
    } else {
        other++
        next
    }
    prefix = substr(line, 1, RSTART - 1)
    n = split(prefix, p, " ")
    if (p[1] ~ /^<[0-9]+>/) {
        when = p[2]
        host = p[3]
    } else {
        when = p[1] " " p[2] " " p[3]
        host = p[4]
    }

    nf = split(csv, f, ",")
    if (nf < 9) {
        malformed++
        next
    }
    version = f[9]
    if (version == 4 && nf >= 20) {
        proto = f[17]
        src = f[19]
        dst = f[20]
        base = 20
    } else if (version == 6 && nf >= 17) {
        proto = f[13]
        src = f[16]
        dst = f[17]
        base = 17
    } else {
        malformed++
        next
    }

    sport = "-"
    dport = "-"
    detail = "-"
    if (proto == "tcp" || proto == "udp") {
        sport = f[base + 1]
        dport = f[base + 2]
        if (proto == "tcp" && f[base + 4] != "") {
            detail = f[base + 4]
        }
    } else if (proto == "icmp" || proto == "ipv6-icmp") {
        if (f[base + 1] != "") {
            detail = f[base + 1]
        }
    }

    if (ip != "" && src != ip && dst != ip) {
        filtered++
        next
    }
    events++
    print when, host, f[1], f[4], f[5], f[7], f[8], version, proto, src, sport, dst, dport, detail
}

END {
    print "STAT", "lines_total", total + 0 > "/dev/stderr"
    print "STAT", "lines_not_filterlog", other + 0 > "/dev/stderr"
    print "STAT", "lines_malformed", malformed + 0 > "/dev/stderr"
    print "STAT", "events_filtered_out", filtered + 0 > "/dev/stderr"
    print "STAT", "events", events + 0 > "/dev/stderr"
}
