"""Documentation checks: links resolve, diagrams are well formed, numbers match the samples, status claims stay honest."""

import re

import pytest

from conftest import ROOT, read_csv, read_events

MARKDOWN = [ROOT / "README.md", ROOT / "TEST_RESULTS.md", ROOT / "screenshots" / "README.md"] + sorted((ROOT / "docs").glob("*.md"))
REQUIRED_DOCS = ["architecture", "addressing-plan", "firewall-policy", "nat-and-vlans", "setup-guide", "connectivity-tests", "log-analysis",
                 "packet-analysis", "siem-integration", "troubleshooting"]


@pytest.mark.parametrize("name", REQUIRED_DOCS)
def test_required_documents_exist_and_have_content(name):
    path = ROOT / "docs" / f"{name}.md"
    assert path.is_file() and path.stat().st_size > 1500


@pytest.mark.parametrize("path", MARKDOWN, ids=lambda p: str(p.relative_to(ROOT)))
def test_relative_links_resolve(path):
    text = path.read_text(encoding="utf-8")
    text = re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)  # image links inside comments are placeholders on purpose
    text = re.sub(r"```.*?```", "", text, flags=re.DOTALL)  # examples inside code blocks are not links
    text = re.sub(r"`[^`\n]*`", "", text)  # nor are examples inside inline code
    for target in re.findall(r"\]\(([^)\s]+)\)", text):
        if target.startswith(("http://", "https://", "mailto:", "#")):
            continue
        resolved = (path.parent / target.split("#")[0]).resolve()
        assert resolved.exists(), f"{path.name}: broken link {target}"


@pytest.mark.parametrize("path", MARKDOWN, ids=lambda p: str(p.relative_to(ROOT)))
def test_code_fences_are_balanced(path):
    fences = [line for line in path.read_text(encoding="utf-8").splitlines() if line.lstrip().startswith("```")]
    assert len(fences) % 2 == 0, f"{path.name}: odd number of code fences"


def test_mermaid_diagrams_are_well_formed():
    count = 0
    for path in MARKDOWN:
        for block in re.findall(r"```mermaid\n(.*?)\n```", path.read_text(encoding="utf-8"), re.DOTALL):
            count += 1
            assert block.split()[0] in {"flowchart", "graph", "sequenceDiagram"}
            for opening, closing in ("[]", "()", "{}"):
                assert block.count(opening) == block.count(closing), f"{path.name}: unbalanced {opening}{closing}"
            assert block.count('"') % 2 == 0, f"{path.name}: unbalanced quotes"
    assert count >= 2


def test_readme_numbers_match_the_samples():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert f"{len(read_events())} synthetic firewall events" in readme
    assert "15 synthetic packets" in readme
    assert f"The {len(read_csv(ROOT / 'samples' / 'lab-expectations.csv'))} safe connectivity tests" in readme


def test_the_documented_rule_table_matches_the_generator_table():
    from conftest import load_module

    generator = load_module("generate_sample_filterlog", "tools/generate_sample_filterlog.py")
    log_doc = (ROOT / "docs" / "log-analysis.md").read_text(encoding="utf-8")
    for number, tracker, interface, action, _ in generator.RULES.values():
        if str(tracker) in log_doc:
            assert f"rule {number}" in log_doc or f"{number}," in log_doc


def test_the_documents_never_claim_a_real_pfsense_run():
    """A sentence that says something was tested on a real pfSense must also say it was NOT (the previous line counts: text wraps)."""
    claim = re.compile(r"(?i)\b(verified|tested|confirmed|validated|ran|run) (on|in|with|against) (a |the )?(real |actual |running )?(pfsense|firewall|vm|lab)\b")
    negation = re.compile(r"(?i)\bnot\b|\bno\b|\bnone\b|\bnever\b|until|\bif\b|\bonly\b|unless|\bor\b|record")
    for path in MARKDOWN:
        lines = path.read_text(encoding="utf-8").splitlines()
        for number, line in enumerate(lines):
            if claim.search(line):
                context = (lines[number - 1] if number else "") + " " + line
                assert negation.search(context), f"{path.name}:{number + 1}: {line}"


def test_status_banners_are_present():
    for name in ("setup-guide", "firewall-policy", "nat-and-vlans", "troubleshooting", "siem-integration"):
        text = (ROOT / "docs" / f"{name}.md").read_text(encoding="utf-8")
        assert "Status" in text[:1200], name
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "No pfSense virtual machine was built" in readme and "synthetic" in readme.lower()


def test_both_paths_are_offered():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "Path A" in readme and "Path B" in readme
    assert "amd64" in readme  # the Apple Silicon note


def test_screenshot_guide_covers_the_readme_placeholders():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    guide = (ROOT / "screenshots" / "README.md").read_text(encoding="utf-8")
    for name in re.findall(r"screenshots/(\d\d-[a-z-]+\.png)", readme):
        assert name in guide, name
    assert not list((ROOT / "screenshots").glob("*.png")), "screenshots must come from a real lab, none may be committed by the generator"
