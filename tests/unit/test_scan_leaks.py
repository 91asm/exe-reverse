"""Unit tests for skills/exe-reverse/scripts/scan_leaks.py.

Two failure modes are tested at once, because only one of them is obvious. A scanner that misses
a pasted key is dangerous; a scanner that flags `x64dbg`, `PE32+` or `192.0.2.44` gets switched
off, which is equally dangerous and much easier to do. So every rule is asserted to fire on a
shaped sample, and every exemption class is asserted to stay quiet.

One measured observation is pinned here rather than hidden: the bare-GUID exemption matches
inside the machine-guid rule's own match text, so that rule cannot produce a finding. The test
asserts the observation, not a wish.
"""
import pathlib

import pytest

pytestmark = pytest.mark.unit


def findings_in(scan_leaks, text):
    """What main() would report: hits that no exemption suppresses."""
    out = []
    for hit in scan_leaks.scan_text(text):
        if scan_leaks.exempt_reason(hit["match"]) or scan_leaks.exempt_reason(hit["context"]):
            continue
        out.append(hit)
    return out


# --- every rule fires --------------------------------------------------------

def test_every_rule_fires_on_its_shaped_sample(load_script, leak_lines):
    scan = load_script("scan_leaks.py")
    missing = []
    for rule, line in leak_lines:
        fired = {hit["rule"] for hit in scan.scan_text(line)}
        if rule not in fired:
            missing.append((rule, line, sorted(fired)))
    assert missing == []


def test_every_rule_except_the_suppressed_one_is_reportable(load_script, leak_lines,
                                                            ):
    scan = load_script("scan_leaks.py")
    suppressed = {"machine-guid"}
    unexpected = []
    for rule, line in leak_lines:
        reported = {hit["rule"] for hit in findings_in(scan, line)}
        if rule in suppressed:
            if rule in reported:
                unexpected.append((rule, "expected to be suppressed by the bare-GUID exemption"))
        elif rule not in reported:
            unexpected.append((rule, "not reported"))
    assert unexpected == []


def test_the_rule_table_is_well_formed(load_script):
    scan = load_script("scan_leaks.py")
    names = [name for _c, _s, name, _p, _w in scan.RULES]
    assert len(names) == len(set(names)) == len(scan.RULES) == 18
    assert {strength for _c, strength, _n, _p, _w in scan.RULES} == {"strong", "weak"}
    for category, strength, name, pattern, why in scan.RULES:
        assert category and name and why, (category, name)
        assert strength in ("strong", "weak")
        assert pattern.pattern, name


# --- the machine-guid observation -------------------------------------------

def test_machine_guid_rule_fires(load_script):
    scan = load_script("scan_leaks.py")
    guid = "3f2a1b4c-5d6e-7f80-9a1b-2c3d4e5f6071"
    hits = scan.scan_text("MachineGuid = %s" % guid)
    assert [h["rule"] for h in hits] == ["machine-guid"]


def test_machine_guid_finding_is_suppressed_by_the_bare_guid_exemption(load_script):
    """Measured: the bare-GUID exemption matches inside this rule's own match text.

    Recorded here so that a change to either list shows up as a test change instead of as a
    silently gained or lost finding.
    """
    scan = load_script("scan_leaks.py")
    line = "MachineGuid = 3f2a1b4c-5d6e-7f80-9a1b-2c3d4e5f6071"
    hit = list(scan.scan_text(line))[0]
    assert scan.exempt_reason(hit["match"]) == \
        "a bare GUID is not machine identity without MachineGuid context"
    assert findings_in(scan, line) == []


def test_a_net_domain_hides_a_hit_behind_the_platform_exemption(load_script):
    """Measured deviation: `.NET` in the platform list matches any `.net` TLD.

    A URL or address under `.net` therefore has its finding suppressed as a platform term,
    which is a false negative rather than a rule. Pinned, not endorsed.
    """
    scan = load_script("scan_leaks.py")
    assert scan.exempt_reason("hexweld.net") == "platform or vendor-of-the-platform term"
    assert scan.exempt_reason("https://licensing.hexweld.net/v2/activate") == \
        "platform or vendor-of-the-platform term"
    # The same shape under a different TLD is reported, which isolates the cause to the TLD.
    hit = list(scan.scan_text("https://licensing.hexweld.org/v2/activate"))
    assert [h["rule"] for h in hit] == ["literal-host-with-path"]
    assert scan.exempt_reason(hit[0]["match"]) is None


def test_the_bracketed_placeholder_form_is_unreachable_in_prose(load_script):
    """Measured: `<[a-z_]+>` sits inside `\\b...\\b`, so bracketed prose never matches."""
    scan = load_script("scan_leaks.py")
    assert scan.exempt_reason("<user>") is None
    assert scan.exempt_reason("a <user> b") is None
    assert scan.PLACEHOLDER_HINT.search("a <user> b") is None
    # Only word-character adjacency reaches it, which is why plain `TARGET` is the form that works.
    assert scan.PLACEHOLDER_HINT.search("x<user>x") is not None
    assert scan.exempt_reason("TARGET") == "placeholder token"


# --- exemptions --------------------------------------------------------------

@pytest.mark.parametrize("sample,reason", [
    ("x64dbg", "tool or library name"),
    ("WinDbg", "tool or library name"),
    ("IDA", "tool or library name"),
    ("CFF Explorer", "tool or library name"),
    ("the copy is packed with UPX", "public protector/packer/managed tooling name"),
    ("Themida", "public protector/packer/managed tooling name"),
    ("IMAGE_NT_HEADERS", "format, standard or platform term"),
    ("CWE-119", "format, standard or platform term"),
    ("Authenticode", "format, standard or platform term"),
    ("Windows", "platform or vendor-of-the-platform term"),
    ("PowerShell", "platform or vendor-of-the-platform term"),
    ("TARGET", "placeholder token"),
    ("YOURAPP", "placeholder token"),
    ("REDACTED", "placeholder token"),
    ("x<user>x", "placeholder token"),
    ("192.0.2.44", "reserved documentation address"),
    ("198.51.100.7", "reserved documentation address"),
    ("203.0.113.9", "reserved documentation address"),
    ("127.0.0.1", "reserved documentation address"),
    ("S-1-5-18", "well-known SID, not a machine identity"),
    ("3f2a1b4c-5d6e-7f80-9a1b-2c3d4e5f6071",
     "a bare GUID is not machine identity without MachineGuid context"),
])
def test_exempt_reason_classifies_the_classes_that_must_stay(load_script, sample, reason):
    assert load_script("scan_leaks.py").exempt_reason(sample) == reason


def test_exempt_reason_does_not_excuse_a_real_finding(load_script):
    """A negative outcome: the exemption list must not swallow target identity."""
    scan = load_script("scan_leaks.py")
    for sample in ("-----BEGIN RSA PRIVATE KEY-----",
                   "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8",
                   "C:\\Users\\mkorvin\\notes.md",
                   "/home/mkorvin/notes.md",
                   "S-1-5-21-1004336348-1177238915-682003330-1001",
                   "Volume Serial Number: 1A2B-3C4D",
                   "hexweld.exe 4.2.1"):
        assert scan.exempt_reason(sample) is None, sample


@pytest.mark.parametrize("label,line", [
    ("tool name", "IDA Pro 9.0.2 opened the image"),
    ("protector name", "the UPX 4.2 stub wraps a Themida section"),
    ("format term", "RVA versus file offset; the PDB is RSDS CodeView"),
    ("platform term", "Microsoft Windows 11.0 build 26100 with PowerShell"),
    ("placeholder token", "TARGET: APP_URL and SAMPLE with PLACEHOLDER values"),
    ("documentation address", "203.0.113.9 and 198.51.100.7 and 192.0.2.44"),
    ("well-known SID", "S-1-5-18 and S-1-5-32-544 are not machine identity"),
    ("loopback and example", "127.0.0.1 and localhost and example.com"),
    ("machine guid context", "MachineGuid = 3f2a1b4c-5d6e-7f80-9a1b-2c3d4e5f6071"),
])
def test_exemption_classes_are_never_reported(load_script, label, line):
    assert findings_in(load_script("scan_leaks.py"), line) == [], label


# --- scan_text ---------------------------------------------------------------

def test_scan_text_reports_position_and_strength(load_script):
    scan = load_script("scan_leaks.py")
    text = "line one is clean\nsecond line: -----BEGIN RSA PRIVATE KEY-----\n"
    hits = list(scan.scan_text(text))
    assert len(hits) == 1
    hit = hits[0]
    assert hit["line"] == 2
    assert hit["col"] == 14
    assert hit["strength"] == "strong"
    assert hit["category"] == "token"
    assert hit["rule"] == "private-key-block"
    assert hit["why"]
    assert "BEGIN RSA PRIVATE KEY" in hit["match"]
    assert hit["context"].startswith("second line:")


def test_clean_text_produces_no_hits_at_all(load_script):
    """A negative outcome: a clean note must not produce a single hit of any strength."""
    scan = load_script("scan_leaks.py")
    text = ("## Triage\n\nRead the section table with peutil.py and printed the entropy.\n"
            "The checksum matched the declared value, so the image was not hand-edited.\n")
    assert list(scan.scan_text(text)) == []


def test_scan_text_does_not_report_the_same_line_as_a_different_rule(load_script):
    scan = load_script("scan_leaks.py")
    hits = scan.scan_text("api_key = \"QwErTyUiOpAsDfGhJkLzXcVb\"")
    assert [h["rule"] for h in hits] == ["generic-secret-assignment"]


# --- file selection ----------------------------------------------------------

def test_iter_files_skips_binaries_and_cache_directories(load_script, tmp_path):
    """A negative outcome: the scanner must not walk binaries, caches or VCS metadata."""
    scan = load_script("scan_leaks.py")
    root = tmp_path / "repo"
    (root / "__pycache__").mkdir(parents=True)
    (root / ".git").mkdir()
    (root / "notes.md").write_text("clean\n", encoding="utf-8")
    (root / "trap.exe").write_bytes(b"-----BEGIN RSA PRIVATE KEY-----\n")
    (root / "trap.png").write_bytes(b"ghp_" + b"A" * 40)
    (root / "__pycache__" / "cached.md").write_text("-----BEGIN RSA PRIVATE KEY-----\n",
                                                    encoding="utf-8")
    (root / ".git" / "config.md").write_text("-----BEGIN RSA PRIVATE KEY-----\n",
                                             encoding="utf-8")
    found = sorted(pathlib.Path(p).relative_to(root).as_posix()
                   for p in scan.iter_files(str(root)))
    assert found == ["notes.md"]


def test_iter_files_honours_an_explicit_file_list(load_script, tmp_path):
    scan = load_script("scan_leaks.py")
    root = tmp_path / "repo"
    root.mkdir()
    (root / "a.md").write_text("a\n", encoding="utf-8")
    (root / "b.md").write_text("b\n", encoding="utf-8")
    listing = tmp_path / "listed.txt"
    listing.write_text("a.md\nmissing.md\n\n", encoding="utf-8")
    found = sorted(pathlib.Path(p).relative_to(root).as_posix()
                   for p in scan.iter_files(str(root), str(listing)))
    assert found == ["a.md"]
