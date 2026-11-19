"""filterlog_summary.sh and filterlog.awk: parsing, summaries, filters and error handling."""

import csv
import io

import pytest

from conftest import FILTERLOG, SUMMARY, parse_line, read_events


def text(result):
    return result.stdout.decode("utf-8")


def test_help_and_version(summary):
    assert b"--format" in summary("--help").stdout
    assert summary("--version").stdout.decode().strip() == "filterlog_summary.sh 1.0.0"


@pytest.mark.parametrize("args, code", [
    ([], 2), (["--bogus"], 2), (["--input", "x", "--format", "xml"], 2), (["--input", "x", "--ip", "1.2.3.4;rm"], 2),
    (["--input", "x", "--top", "0"], 2), (["--input", "x", "--top", "abc"], 2),
])
def test_invalid_options_exit_with_2(summary, args, code):
    assert summary(*args).returncode == code


def test_missing_and_unreadable_input_exit_with_3(summary, tmp_path):
    assert summary("--input", tmp_path / "nope.log").returncode == 3
    assert summary("--input", tmp_path).returncode == 3  # a directory


def test_text_summary_numbers(summary):
    result = summary("--input", FILTERLOG)
    assert result.returncode == 0, result.stderr
    out = text(result)
    assert "Lines read   : 118 (not filterlog: 0, malformed: 0)" in out
    for expected in ("em0    block      14", "em0    pass       60", "em1    block       3", "em1    pass       22",
                     "em2    block       6", "em2    pass        2", "em3    pass       11"):
        assert expected in out
    assert "14  198.51.100.23" in out and "6  10.10.20.10" in out and "3  10.10.10.20" in out
    assert "9  10.10.10.20 -> 203.0.113.45:443" in out
    assert "60  rule 98   tracker 1710410101   pass" in out and "14  rule 12   tracker 1000000103   block" in out


def test_csv_matches_an_independent_python_parser(summary):
    result = summary("--input", FILTERLOG, "--format", "csv")
    rows = list(csv.DictReader(io.StringIO(text(result))))
    expected = read_events()
    assert len(rows) == len(expected) == 118
    for row, event in zip(rows, expected):
        assert (row["interface"], row["action"], row["protocol"], row["src_ip"], row["dst_ip"], row["src_port"], row["dst_port"],
                row["detail"], row["rule"], row["tracker"]) == (event["interface"], event["action"], event["protocol"], event["src_ip"],
                event["dst_ip"], event["src_port"], event["dst_port"], event["detail"], event["rule"], event["tracker"])


def test_ip_filter_pivots_on_one_address(summary):
    out = text(summary("--input", FILTERLOG, "--ip", "203.0.113.45"))
    assert "Events       : 69" in out and "em0    pass       60" in out and "em1    pass        9" in out
    rows = list(csv.DictReader(io.StringIO(text(summary("--input", FILTERLOG, "--ip", "10.10.20.10", "--format", "csv")))))
    assert rows and all("10.10.20.10" in (r["src_ip"], r["dst_ip"]) for r in rows)
    assert len(rows) == sum("10.10.20.10" in (e["src_ip"], e["dst_ip"]) for e in read_events())


def test_top_option_limits_the_lists(summary):
    out = text(summary("--input", FILTERLOG, "--top", "2"))
    assert "Top 2 blocked sources" in out
    section = out.split("Top 2 blocked destination ports")[1].split("Allowed connections")[0]
    assert len([line for line in section.splitlines() if line.strip()]) == 2


def test_standard_input_and_missing_final_newline(summary):
    data = FILTERLOG.read_bytes().rstrip(b"\n")
    result = summary("--input", "-", "--format", "csv", stdin=data)
    assert len(text(result).splitlines()) == 119  # header + 118 events, the last line was not lost


def test_rfc5424_lines_and_ipv6_and_junk(summary):
    lines = [
        "<134>1 2026-03-14T09:12:03.123456+00:00 pfsense-lab filterlog 84921 - - 12,,,1000000103,em0,match,block,in,4,0x0,,52,1,0,DF,6,tcp,60,198.51.100.23,203.0.113.10,44406,23,0,S,1,,64240,,mss",
        "<134>Mar 14 09:12:03 pfsense-lab filterlog[84921]: 12,,,1000000103,em0,match,block,in,6,0x00,0x00000,64,tcp,6,40,2001:db8::1,2001:db8::2,5555,80,0,S,1,,1000,,mss",
        "Mar 14 09:12:04 pfsense-lab dhcpd[1]: DHCPACK on 10.10.10.20",
        "Mar 14 09:12:05 pfsense-lab filterlog[84921]: 12,,,short",
    ]
    result = summary("--input", "-", "--format", "csv", stdin="\n".join(lines).encode())
    rows = list(csv.DictReader(io.StringIO(text(result))))
    assert [r["src_ip"] for r in rows] == ["198.51.100.23", "2001:db8::1"]
    assert rows[0]["time"] == "2026-03-14T09:12:03.123456+00:00" and rows[1]["ip_version"] == "6"
    out = text(summary("--input", "-", stdin="\n".join(lines).encode()))
    assert "Lines read   : 4 (not filterlog: 1, malformed: 1)" in out  # the DHCP line is not a firewall event, the short one is malformed


def test_empty_file_and_crlf(summary, tmp_path):
    empty = tmp_path / "empty.log"
    empty.write_bytes(b"")
    assert "Events       : 0" in text(summary("--input", empty))
    crlf = tmp_path / "crlf.log"
    crlf.write_bytes(FILTERLOG.read_bytes().replace(b"\n", b"\r\n"))
    result = summary("--input", crlf, "--format", "csv")
    assert result.returncode == 0 and len(text(result).splitlines()) >= 118


def test_paths_with_spaces_and_hebrew_characters(summary, tmp_path):
    folder = tmp_path / "לוגים של חומת אש"
    folder.mkdir()
    target = folder / "my filter.log"
    target.write_bytes(FILTERLOG.read_bytes())
    for locale in ({}, {"LANG": "en_US.UTF-8", "LC_ALL": "en_US.UTF-8"}):
        result = summary("--input", target, env_extra=locale)
        assert result.returncode == 0 and "Events       : 118" in text(result)


def test_file_named_like_an_awk_assignment_is_read_as_a_file(summary, tmp_path):
    tricky = tmp_path / "x=1"
    tricky.write_bytes(FILTERLOG.read_bytes())
    assert "Events       : 118" in text(summary("--input", tricky))


def test_unknown_awk_is_reported(summary):
    result = summary("--input", FILTERLOG, env_extra={"FILTERLOG_AWK": "no-such-awk"})
    assert result.returncode == 3 and b"awk not found" in result.stderr


def test_input_file_is_never_modified(summary, tmp_path):
    target = tmp_path / "keep.log"
    target.write_bytes(FILTERLOG.read_bytes())
    before = (target.read_bytes(), target.stat().st_mtime_ns)
    summary("--input", target)
    summary("--input", target, "--format", "csv")
    assert (target.read_bytes(), target.stat().st_mtime_ns) == before
    assert not list(tmp_path.glob("filterlog.*"))  # temporary directory removed
