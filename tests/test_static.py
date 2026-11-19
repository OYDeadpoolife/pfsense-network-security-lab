"""Repository hygiene: required files, safe scripts, no secrets or personal data, lint."""

import re
import shutil
import subprocess

import pytest

from conftest import ROOT

REQUIRED_FILES = [
    "README.md", "LICENSE", ".gitignore", ".editorconfig", "Makefile", "requirements-dev.txt", "TEST_RESULTS.md",
    "scripts/filterlog_summary.sh", "scripts/filterlog.awk", "scripts/lab_connectivity_test.sh",
    "tools/generate_sample_filterlog.py", "tools/generate_synthetic_pcap.py", "tools/extract_scenario_connections.py",
    "samples/filterlog_sample.log", "samples/synthetic_scan_and_ssh.pcap", "samples/lab-expectations.csv",
    "samples/scenario_ssh_connections.csv", "samples/scenario_ws01_connections.csv",
    "siem/splunk_filterlog.spl", "siem/logstash-pfsense.conf.example", "siem/filebeat-syslog.yml.example",
    "screenshots/README.md", ".github/workflows/ci.yml",
]
SHELL_FILES = ["scripts/filterlog_summary.sh", "scripts/lab_connectivity_test.sh"]
# Written in pieces so this file does not match itself; the last marker is the account name used while developing.
LOCAL_PATH_MARKERS = ("/Use" + "rs/", "orhay" + "yosef")


@pytest.mark.parametrize("relative", REQUIRED_FILES)
def test_required_file_exists(relative):
    assert (ROOT / relative).is_file(), relative


def test_scripts_are_executable():
    import os

    for relative in SHELL_FILES:
        assert os.access(ROOT / relative, os.X_OK)


def test_scripts_never_use_privileges_or_install_software():
    forbidden = re.compile(r"^\s*(sudo|su|apt|apt-get|brew|pip3?|curl|wget|chown|chmod)\b")
    for relative in SHELL_FILES + ["scripts/filterlog.awk"]:
        for number, line in enumerate((ROOT / relative).read_text(encoding="utf-8").splitlines(), 1):
            assert not forbidden.match(line), f"{relative}:{number}: {line}"
            assert "eval " not in line


def test_the_only_deleting_command_removes_the_temporary_directory():
    uses = []
    for relative in SHELL_FILES:
        for line in (ROOT / relative).read_text(encoding="utf-8").splitlines():
            code = line.split("#", 1)[0]
            if re.search(r"\b(rm|rmdir|mv|dd|shred|truncate)\b", code):
                uses.append(code.strip())
    assert uses == ["trap 'rm -rf -- \"$work\"' EXIT"], uses


def test_no_secrets_or_personal_data():
    patterns = [r"-----BEGIN [A-Z ]*PRIVATE KEY-----", r"AKIA[0-9A-Z]{16}", r"ghp_[A-Za-z0-9]{36}", r"xox[baprs]-[A-Za-z0-9-]+"]
    for path in ROOT.rglob("*"):
        if not path.is_file() or {".git", ".pytest_cache", "__pycache__"} & set(path.relative_to(ROOT).parts) or path.suffix == ".pcap":
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for pattern in patterns:
            assert not re.search(pattern, text), f"possible secret in {path.relative_to(ROOT)}"
        for marker in LOCAL_PATH_MARKERS:
            assert marker not in text, f"local path or account name in {path.relative_to(ROOT)}"


def test_only_the_synthetic_capture_is_committed():
    captures = [p.name for p in ROOT.rglob("*") if p.suffix in (".pcap", ".pcapng") and ".git" not in p.parts]
    assert captures == ["synthetic_scan_and_ssh.pcap"]
    assert not list(ROOT.rglob("config-*.xml"))


def test_no_backup_or_cache_files():
    # Interpreter caches (__pycache__) are created by running the tests themselves and are ignored by .gitignore.
    skip = {".git", "__pycache__", ".pytest_cache"}
    names = [p.name for p in ROOT.rglob("*") if p.is_file() and not skip.intersection(p.parts)]
    assert not [n for n in names if n.endswith((".orig", ".bak", ".swp", ".pyc"))]


@pytest.mark.skipif(shutil.which("shellcheck") is None, reason="shellcheck is not installed")
def test_shellcheck_is_clean():
    assert subprocess.run(["shellcheck", "-x", *SHELL_FILES], cwd=ROOT, capture_output=True, text=True).returncode == 0


@pytest.mark.skipif(shutil.which("shfmt") is None, reason="shfmt is not installed")
def test_shfmt_is_clean():
    assert subprocess.run(["shfmt", "-d", "-i", "4", "-ci", *SHELL_FILES], cwd=ROOT, capture_output=True, text=True).returncode == 0
