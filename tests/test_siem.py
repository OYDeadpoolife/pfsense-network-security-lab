"""SIEM files: the Splunk regular expression is tested against the sample log; configuration examples are checked statically."""

import re

from conftest import FILTERLOG, ROOT, parse_line

SPL = (ROOT / "siem" / "splunk_filterlog.spl").read_text(encoding="utf-8")


def spl_regexes():
    return re.findall(r'\| rex "(.*)"$', SPL, re.MULTILINE)


def to_python(pattern):
    return pattern.replace("(?<", "(?P<")  # Splunk (PCRE) writes named groups as (?<name>...), Python as (?P<name>...)


def test_every_search_uses_the_same_extraction():
    patterns = spl_regexes()
    assert len(patterns) == 7 and len(set(patterns)) == 1


def test_the_regex_extracts_every_field_of_every_ipv4_line():
    regex = re.compile(to_python(spl_regexes()[0]))
    for line in FILTERLOG.read_text(encoding="utf-8").splitlines():
        match = regex.search(line)
        assert match, line
        event = parse_line(line)
        assert (match["rule"], match["tracker"], match["interface"], match["action"], match["protocol"], match["src_ip"], match["dest_ip"]) == (
            event["rule"], event["tracker"], event["interface"], event["action"], event["protocol"], event["src_ip"], event["dst_ip"])
        if event["protocol"] in ("tcp", "udp"):
            assert (match["src_port"], match["dest_port"]) == (event["src_port"], event["dst_port"])
        else:
            assert match["src_port"] is None  # ICMP lines have no ports


def test_the_regex_also_matches_the_remote_syslog_form_with_a_priority_prefix():
    regex = re.compile(to_python(spl_regexes()[0]))
    line = "<134>" + FILTERLOG.read_text(encoding="utf-8").splitlines()[5]
    assert regex.search(line)["action"] in ("pass", "block")


def test_searches_are_read_only_and_marked_not_tested():
    assert "NOT TESTED in Splunk" in SPL
    body = "\n".join(l for l in SPL.splitlines() if not l.startswith("#"))
    for command in ("delete", "outputlookup", "collect", "sendemail", "script", "map"):
        assert not re.search(rf"\|\s*{command}\b", body)
    assert body.count("index=soc_lab sourcetype=pfsense:filterlog") == 7


def test_expected_numbers_quoted_in_the_searches_match_the_sample():
    from collections import Counter

    from conftest import read_events

    events = read_events()
    assert Counter((e["interface"], e["action"]) for e in events) == {("em0", "pass"): 60, ("em0", "block"): 14, ("em1", "pass"): 22,
                                                                       ("em1", "block"): 3, ("em2", "pass"): 2, ("em2", "block"): 6, ("em3", "pass"): 11}
    for fragment in ("em0 pass 60 / block 14", "em1 pass 22 / block 3", "em2 pass 2 / block 6", "em3 pass 11"):
        assert fragment in SPL


def test_logstash_columns_follow_the_documented_field_order():
    text = (ROOT / "siem" / "logstash-pfsense.conf.example").read_text(encoding="utf-8")
    columns = re.findall(r'"([a-z_]+)"', text[text.index("columns"):text.index("]", text.index("columns"))])
    assert columns[:9] == ["rule", "sub_rule", "anchor", "tracker", "interface", "reason", "action", "direction", "ip_version"]
    assert columns.index("src_ip") == 18 and columns.index("dst_ip") == 19 and columns.index("src_port") == 20 and columns.index("tcp_flags") == 23


def test_configuration_examples_are_marked_untested_and_contain_no_secrets():
    for name in ("logstash-pfsense.conf.example", "filebeat-syslog.yml.example"):
        text = (ROOT / "siem" / name).read_text(encoding="utf-8")
        assert "NOT TESTED" in text
        for line in text.splitlines():
            if re.match(r"\s*(api_key|password)\s*(=>|:)", line):
                assert "${ES_API_KEY}" in line, line
