"""lab_connectivity_test.sh: safety guards, parsing and PASS/FAIL logic (tested against a local listener, never a real lab)."""

import socket
import subprocess

import pytest

from conftest import CONNECTIVITY, ROOT, SAMPLES, read_csv

HEADER = "test_id,source_zone,description,protocol,target_ip,port,expected,reason\n"


def run(*args, cwd=None):
    return subprocess.run([str(CONNECTIVITY), *map(str, args)], capture_output=True, text=True, cwd=cwd, timeout=60)


@pytest.fixture
def listener():
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(5)
    yield server.getsockname()[1]
    server.close()


def closed_port():
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


def write_csv(tmp_path, *rows):
    path = tmp_path / "expectations.csv"
    path.write_text("# a comment line\n" + HEADER + "\n".join(rows) + "\n", encoding="utf-8")
    return path


def test_committed_expectations_are_inside_the_lab_and_well_formed():
    rows = read_csv(SAMPLES / "lab-expectations.csv")
    assert len(rows) == 15
    assert {r["source_zone"] for r in rows} == {"LAN", "DMZ", "MGMT", "WAN"}
    for row in rows:
        assert row["target_ip"].startswith(("10.10.", "203.0.113.")), row
        assert row["protocol"] in ("tcp", "icmp") and row["expected"] in ("allow", "block")
        assert 0 <= int(row["port"]) <= 65535


def test_the_documentation_lists_exactly_the_same_tests_and_results():
    doc = (ROOT / "docs" / "connectivity-tests.md").read_text(encoding="utf-8")
    for row in read_csv(SAMPLES / "lab-expectations.csv"):
        line = next(l for l in doc.splitlines() if l.startswith(f"| {row['test_id']} |"))
        cells = [c.strip().strip("*") for c in line.strip("|").split("|")]
        assert cells[2].endswith(f"{row['target_ip']}:{row['port']}") or row["target_ip"] in cells[2], line
        assert cells[3] == row["expected"], f"{row['test_id']}: documented {cells[3]}, CSV says {row['expected']}"


def test_help_version_and_option_errors():
    assert "--confirm-lab" in run("--help").stdout
    assert run("--version").stdout.strip() == "lab_connectivity_test.sh 1.0.0"
    assert run("--zone", "DMZ", "--bogus").returncode == 2
    assert run("--zone", "elsewhere", "--dry-run").returncode == 2
    assert run().returncode == 2


def test_dry_run_and_list_send_nothing_and_need_no_confirmation():
    for flag in ("--dry-run", "--list"):
        result = run("--zone", "DMZ", flag)
        assert result.returncode == 0 and "T10" in result.stdout and "expect block" in result.stdout
    assert "dry run: nothing was sent" in run("--zone", "WAN", "--dry-run").stdout


def test_refuses_to_send_without_confirmation():
    result = run("--zone", "LAN")
    assert result.returncode == 2 and "--confirm-lab" in result.stderr


@pytest.mark.parametrize("target", ["8.8.8.8", "192.168.1.1", "10.11.0.1", "203.0.114.5", "127.0.0.1", "10.10.1.999", "example.com"])
def test_refuses_any_target_outside_the_lab(tmp_path, target):
    """A file that mentions a forbidden address is rejected as a whole, before any traffic is sent."""
    path = write_csv(tmp_path, "T1,LAN,fine,tcp,10.10.10.1,53,allow,x", f"T2,LAN,not allowed,tcp,{target},80,allow,x")
    result = run("--zone", "LAN", "--confirm-lab", "-e", path)
    assert result.returncode == 2 and "refusing target" in result.stderr
    assert "Running" not in result.stdout and "PASS" not in result.stdout


def test_loopback_is_only_accepted_with_the_explicit_flag(tmp_path, listener):
    path = write_csv(tmp_path, f"T1,LAN,local listener,tcp,127.0.0.1,{listener},allow,x")
    assert run("--zone", "LAN", "--confirm-lab", "-e", path).returncode == 2
    assert run("--zone", "LAN", "--confirm-lab", "--allow-loopback", "-e", path, "-t", "1").returncode == 0


def test_pass_fail_logic_and_exit_status(tmp_path, listener):
    path = write_csv(tmp_path,
                     f"T1,LAN,open port,tcp,127.0.0.1,{listener},allow,listener",
                     f"T2,LAN,closed port,tcp,127.0.0.1,{closed_port()},block,nothing listens",
                     f"T3,LAN,wrong expectation,tcp,127.0.0.1,{listener},block,deliberate",
                     f"T9,DMZ,other zone,tcp,127.0.0.1,{listener},block,must not run")
    result = run("--zone", "LAN", "--confirm-lab", "--allow-loopback", "-e", path, "-t", "1")
    assert result.returncode == 1
    assert "PASS T1" in result.stdout and "PASS T2" in result.stdout and "FAIL T3" in result.stdout
    assert "T9" not in result.stdout  # only the requested zone runs
    assert "3 test(s), 2 matched the design, 1 did not." in result.stdout


def test_all_matching_tests_give_exit_status_zero(tmp_path, listener):
    path = write_csv(tmp_path, f"T1,LAN,open port,tcp,127.0.0.1,{listener},allow,x", f"T2,LAN,closed,tcp,127.0.0.1,{closed_port()},block,x")
    assert run("--zone", "LAN", "--confirm-lab", "--allow-loopback", "-e", path, "-t", "1").returncode == 0


def test_icmp_to_loopback_is_allowed(tmp_path):
    path = write_csv(tmp_path, "T1,LAN,ping myself,icmp,127.0.0.1,0,allow,x")
    result = run("--zone", "LAN", "--confirm-lab", "--allow-loopback", "-e", path, "-t", "2")
    assert "PASS T1" in result.stdout, result.stdout + result.stderr


@pytest.mark.parametrize("row, message", [
    ("T1,LAN,x,udp,10.10.10.1,53,allow,x", "protocol must be tcp or icmp"),
    ("T1,LAN,x,tcp,10.10.10.1,99999,allow,x", "invalid port"),
    ("T1,LAN,x,tcp,10.10.10.1,53,maybe,x", "expected must be allow or block"),
])
def test_invalid_rows_are_rejected(tmp_path, row, message):
    result = run("--zone", "LAN", "--list", "-e", write_csv(tmp_path, row))
    assert result.returncode == 3 and message in result.stderr


def test_missing_file_zone_without_tests_and_comments(tmp_path):
    assert run("--zone", "LAN", "--list", "-e", tmp_path / "nope.csv").returncode == 3
    only_lan = write_csv(tmp_path, "T1,LAN,x,tcp,10.10.10.1,53,allow,x")
    assert run("--zone", "WAN", "--list", "-e", only_lan).returncode == 3
    assert "T1" in run("--zone", "LAN", "--list", "-e", only_lan).stdout


def test_script_never_modifies_anything(tmp_path, listener):
    path = write_csv(tmp_path, f"T1,LAN,open,tcp,127.0.0.1,{listener},allow,x")
    before = sorted(p.name for p in tmp_path.iterdir())
    run("--zone", "LAN", "--confirm-lab", "--allow-loopback", "-e", path, "-t", "1", cwd=tmp_path)
    assert sorted(p.name for p in tmp_path.iterdir()) == before
