"""Shared fixtures for the exe-reverse regression suite.

What this file guarantees:

* every input is *built*, never committed and never downloaded -- the synthetic PE images come
  from ``skills/exe-reverse/scripts/make_fixture_pe.py`` at test time, into a pytest temporary
  directory that disappears with the session;
* the scripts under test are loaded by path, because ``skills/exe-reverse/scripts/`` is a flat
  directory of runnable files, not an importable package;
* a missing prerequisite -- an older interpreter, an absent local tool -- is a *skip with a
  printed reason*, never a failure. A wrong result is always a failure.

Nothing here touches the network, a debugger, a device or a kernel component.
"""
import hashlib
import importlib.util
import json
import os
import pathlib
import shutil
import subprocess
import sys

import pytest

TESTS_DIR = pathlib.Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parent
SCRIPTS_DIR = REPO_ROOT / "skills" / "exe-reverse" / "scripts"

# The scripts declare "Python 3.9+" in their own docstrings.
MIN_PYTHON = (3, 9)

SCRIPT_FILES = (
    "peutil.py",
    "pepatch.py",
    "hwprobe.py",
    "aob_scan.py",
    "make_fixture_pe.py",
    "scan_leaks.py",
)

# A hang detector, not a performance assertion. Nothing in this suite is meant to be slow.
RUN_TIMEOUT = 180

# Suite name -> recipe name in make_fixture_pe.py, so recipes are referenced rather than
# duplicated. `default` is PE32+ with every structure; `pe32` is the 32-bit layout; `bare`
# drops exports/resources/TLS/debug; `fatalign` uses a 4 KiB file alignment, which is large
# enough that .rdata has no virtual-only tail at all.
#
# The `no-virtual-tail` recipe is deliberately NOT used: with `rdata_virtual_pad = 0` its own
# guard (`rdata_payload_len > rdata_virtual_pad`) rejects the layout it names, so the recipe
# cannot be built and exits 1. `fatalign` covers the same property. Recorded in benchmark.md.
FIXTURE_RECIPES = {
    "pe64": "default",
    "pe32": "pe32",
    "bare": "bare",
    "fatalign": "fat-align",
}

# --- synthetic leak corpus ---------------------------------------------------
# One line per rule in scan_leaks.py. Each line is shaped like the thing its rule targets, and
# (except for machine-guid, which is a measured observation -- see the unit tests) is not
# suppressed by the exemption list.
#
# Every sample is assembled from fragments at import time rather than quoted whole. The suite
# deliberately contains strings shaped like a pasted key, a token and a real profile path; if
# they were written whole, the repository's own pre-publish scan would report this file the
# moment it walked the tracked surface. Splitting them keeps the runtime value matched by the
# rule while the source text matches nothing. A scanner's own fixtures have to be written this
# way, and that is a property of the scan surface, not a trick.
def parts(*chunks):
    """Join string fragments at run time (see the note above)."""
    return "".join(chunks)


LEAK_LINES = (
    ("private-key-block", parts("-----BEGIN RSA ", "PRIVATE KEY-----")),
    ("github-token", parts("ghp_", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8")),
    ("aws-access-key", parts("AKIA", "Q7ZK3MNP2RVW8XTD")),
    ("slack-token", parts("xoxb-", "1234567890abcdef")),
    ("generic-secret-assignment", parts('api_key = "', "QwErTyUiOpAsDfGhJkLzXcVb", '"')),
    ("licence-blob-literal", parts('license_key: "', "ABCDEFGH1234", '"')),
    ("windows-user-profile", parts("C:\\Users\\", "mkorvin", "\\notes.md")),
    ("posix-home", parts("/home/", "mkorvin", "/notes.md")),
    ("machine-guid", parts("MachineGuid = ", "3f2a1b4c-5d6e-7f80-9a1b-2c3d4e5f6071")),
    ("windows-sid-literal", parts("S-1-5-21-", "1004336348-1177238915-682003330-", "1001")),
    ("volume-serial-literal", parts("Volume Serial Number: ", "1A2B-3C4D")),
    ("literal-endpoint-with-creds", parts("ftp://", "deploy:Sup3rSecret@", "45.77.", "10.199/pub")),
    ("public-ipv4-literal", parts("45.77.", "10.199")),
    ("literal-host-with-path", parts("https://licensing.", "hexweld.", "org/v2/activate")),
    ("product-name-with-version", parts("Hexweld Editor ", "4.2.1")),
    ("exe-name-with-version", parts("build: hexweld", ".exe v4.2")),
    ("email-address", parts("k.morozov@", "hexweld.org")),
    ("vendor-copyright-line", parts("Copyright (c) 2024 ", "Hexweld Systems")),
)

# Lines that must never be reported: tool names, protector names, format vocabulary, platform
# terms, placeholder tokens, reserved documentation addresses, well-known SIDs.
EXEMPT_LINES = (
    ("tool name", "IDA Pro 9.0.2 opened the image"),
    ("protector name", "the UPX 4.2 stub wraps a Themida section"),
    ("format term", "RVA versus file offset; the PDB is RSDS CodeView"),
    ("platform term", "Microsoft Windows 11.0 build 26100 with PowerShell"),
    ("placeholder token", "TARGET: APP_URL and SAMPLE with PLACEHOLDER values"),
    ("documentation address", "203.0.113.9 and 198.51.100.7 and 192.0.2.44"),
    ("well-known SID", "S-1-5-18 and S-1-5-32-544 are not machine identity"),
    ("loopback and example", "127.0.0.1 and localhost and example.com"),
    ("machine guid context", parts("MachineGuid = ", "3f2a1b4c-5d6e-7f80-9a1b-2c3d4e5f6071")),
    ("net tld", parts("https://licensing.", "hexweld.", "net/v2/activate")),
)

# Measured deviations from the exemption list, pinned as observations rather than wishes. Each
# is asserted by a unit test so a change to either list is visible instead of silent:
#   * the bare-GUID exemption matches inside the machine-guid rule's own match text, so that
#     rule cannot produce a finding;
#   * the `.NET` entry matches any `.net` TLD, so a hit inside such a URL or address is
#     suppressed as a platform term;
#   * the `<[a-z_]+>` placeholder alternative is surrounded by `\b` on both sides, so it cannot
#     match bracketed prose; only word-character adjacency reaches it.
#
# A fourth deviation was measured and then corrected while this suite was being written: for one
# revision of the exemption list, a standard-name alternative matched the `HTTP` inside every
# `https?://` URL and swallowed every literal-host-with-path hit. benchmark.md records both
# states; the suite asserts the corrected one.
SUPPRESSED_RULES = ("machine-guid",)

# Lines that must never be reported: tool names, protector names, format vocabulary, platform
# terms, placeholder tokens, reserved documentation addresses, well-known SIDs.
EXEMPT_LINES = (
    ("tool name", "IDA Pro 9.0.2 opened the image"),
    ("protector name", "the UPX 4.2 stub wraps a Themida section"),
    ("format term", "RVA versus file offset; the PDB is RSDS CodeView"),
    ("platform term", "Microsoft Windows 11.0 build 26100 with PowerShell"),
    ("placeholder token", "TARGET: APP_URL and SAMPLE with PLACEHOLDER values"),
    ("documentation address", "203.0.113.9 and 198.51.100.7 and 192.0.2.44"),
    ("well-known SID", "S-1-5-18 and S-1-5-32-544 are not machine identity"),
    ("loopback and example", "127.0.0.1 and localhost and example.com"),
    ("machine guid context", "MachineGuid = 3f2a1b4c-5d6e-7f80-9a1b-2c3d4e5f6071"),
    ("net tld", "https://licensing.hexweld.net/v2/activate"),
)

# The one rule whose hits are suppressed by the exemption list. Measured, not assumed: the
# bare-GUID exemption matches inside the machine-guid rule's own match text. Pinned by a unit
# test so a change in either list is visible instead of silent.
SUPPRESSED_RULES = ("machine-guid",)


def pytest_report_header(config):
    return [
        "exe-reverse suite: python %s, scripts %s" % (sys.version.split()[0], SCRIPTS_DIR),
    ]


class ScriptResult(object):
    """One script run: returncode, stdout, stderr, plus the argv that produced it."""

    __slots__ = ("returncode", "stdout", "stderr", "argv")

    def __init__(self, returncode, stdout, stderr, argv):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.argv = argv

    def __iter__(self):
        return iter((self.returncode, self.stdout, self.stderr))

    def __repr__(self):
        return "ScriptResult(returncode=%r, argv=%r)" % (self.returncode, self.argv)


class BuiltFixture(object):
    """A generated fixture image plus the metadata make_fixture_pe.py returned for it."""

    __slots__ = ("name", "path", "meta", "recipe")

    def __init__(self, name, path, meta, recipe):
        self.name = name
        self.path = path
        self.meta = meta
        self.recipe = recipe

    @property
    def data(self):
        return self.path.read_bytes()

    @property
    def size(self):
        return len(self.data)

    @property
    def sha256(self):
        return hashlib.sha256(self.data).hexdigest()

    @property
    def plant(self):
        """The byte sequence planted twice in .text, as a spaced hex string."""
        return self.meta["plant"]["bytes"]

    @property
    def plant_offsets(self):
        return (int(self.meta["plant"]["first_file_offset"], 16),
                int(self.meta["plant"]["second_file_offset"], 16))

    def section(self, name):
        return self.meta["sections"][name]

    def __repr__(self):
        return "BuiltFixture(%r, %s)" % (self.name, self.path)


class FixtureSet(object):
    """Attribute and index access to the built fixtures."""

    def __init__(self, items):
        self._items = dict(items)

    def __getattr__(self, name):
        try:
            return self._items[name]
        except KeyError:
            raise AttributeError(name)

    def __getitem__(self, name):
        return self._items[name]

    def names(self):
        return sorted(self._items)


@pytest.fixture(scope="session", autouse=True)
def interpreter_gate():
    """Skip everything, with a reason, when the interpreter is older than the scripts require."""
    if sys.version_info < MIN_PYTHON:
        pytest.skip("skills/exe-reverse/scripts declare Python %d.%d+; this session is running "
                    "%s -- install a newer interpreter to exercise the suite"
                    % (MIN_PYTHON[0], MIN_PYTHON[1], sys.version.split()[0]))


@pytest.fixture(scope="session")
def require_local_tool():
    """Skip a check, with a reason, when a tool it needs is not installed."""

    def _need(tool):
        found = shutil.which(tool)
        if not found:
            pytest.skip("local tool %r is not on PATH; this check is inert without it" % tool)
        return found

    return _need


@pytest.fixture(scope="session")
def load_script():
    """Import a tested script by path, once per session.

    ``pepatch.py`` and ``aob_scan.py`` put their own directory on ``sys.path`` and then import
    ``peutil`` by bare name. Registering one shared module per name keeps a single PE class in
    the process instead of two classes that compare unequal.
    """
    cache = {}

    def _load(filename):
        if filename not in SCRIPT_FILES:
            raise ValueError("%r is not one of the tested scripts: %r" % (filename, SCRIPT_FILES))
        name = filename[:-3]
        if name in cache:
            return cache[name]
        if str(SCRIPTS_DIR) not in sys.path:
            sys.path.insert(0, str(SCRIPTS_DIR))
        spec = importlib.util.spec_from_file_location(name, SCRIPTS_DIR / filename)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        cache[name] = module
        return module

    return _load


@pytest.fixture(scope="session")
def run_script():
    """Run a tested script as a subprocess and return (returncode, stdout, stderr)."""

    def _run(filename, *args, **kwargs):
        if filename not in SCRIPT_FILES:
            raise ValueError("%r is not one of the tested scripts: %r" % (filename, SCRIPT_FILES))
        timeout = kwargs.pop("timeout", RUN_TIMEOUT)
        cwd = kwargs.pop("cwd", None)
        if kwargs:
            raise TypeError("unexpected keyword arguments: %r" % sorted(kwargs))
        argv = [sys.executable, str(SCRIPTS_DIR / filename)] + [str(a) for a in args]
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                                  cwd=cwd, encoding="utf-8", errors="replace")
        except subprocess.TimeoutExpired:
            pytest.fail("%s did not finish within %ds: %r" % (filename, timeout, argv))
        return ScriptResult(proc.returncode, proc.stdout, proc.stderr, argv)

    return _run


@pytest.fixture(scope="session")
def fixture_dir(tmp_path_factory):
    return tmp_path_factory.mktemp("exe-reverse-fixtures")


@pytest.fixture(scope="session")
def build_fixture(fixture_dir, load_script, run_script):
    """Build one named fixture through the real CLI and cross-check it against build_pe()."""
    maker = load_script("make_fixture_pe.py")
    cache = {}

    def _build(name):
        if name in cache:
            return cache[name]
        if name not in FIXTURE_RECIPES:
            raise ValueError("unknown fixture %r; known: %r" % (name, sorted(FIXTURE_RECIPES)))
        recipe = FIXTURE_RECIPES[name]
        dest = fixture_dir / (name + ".exe")
        result = run_script("make_fixture_pe.py", "--out", dest, "--recipe", recipe)
        if result.returncode != 0:
            pytest.fail("make_fixture_pe.py --recipe %s failed with %d: %s"
                        % (recipe, result.returncode, result.stderr))
        data, meta = maker.build_pe(**maker.RECIPES[recipe])
        if dest.read_bytes() != data:
            pytest.fail("make_fixture_pe.py wrote bytes that differ from its own build_pe() "
                        "output -- the CLI and the library disagree")
        built = BuiltFixture(name, dest, meta, recipe)
        cache[name] = built
        return built

    return _build


@pytest.fixture(scope="session")
def fixtures(build_fixture):
    """The four generated images, addressed as ``fixtures.pe64`` / ``fixtures['pe32']``."""
    return FixtureSet({name: build_fixture(name) for name in FIXTURE_RECIPES})


@pytest.fixture(scope="session")
def hwprobe_report(run_script):
    """One host capability report for the whole session.

    The probe executes a CPUID stub, so re-running it per assertion would buy nothing and cost
    seconds. It is a host fact, not a per-test one.
    """
    result = run_script("hwprobe.py", "--json")
    if result.returncode != 0:
        pytest.fail("hwprobe.py --json exited %d: %s" % (result.returncode, result.stderr))
    return json.loads(result.stdout)


@pytest.fixture(scope="session")
def hexpat():
    """Render bytes as the spaced hex form the scripts accept."""

    def _hexpat(obj):
        if isinstance(obj, str):
            return " ".join("%02X" % b for b in obj.encode("latin-1"))
        return " ".join("%02X" % b for b in bytearray(obj))

    return _hexpat


@pytest.fixture(scope="session")
def leak_lines():
    return LEAK_LINES


@pytest.fixture(scope="session")
def exempt_lines():
    return EXEMPT_LINES


@pytest.fixture(scope="session")
def weak_line(leak_lines):
    """A sample that produces exactly one weak finding and no strong one."""
    return dict(leak_lines)["vendor-copyright-line"]


@pytest.fixture(scope="session")
def strong_line(leak_lines):
    """A sample that produces a strong finding."""
    return dict(leak_lines)["windows-user-profile"]


@pytest.fixture
def synthetic_leak_root(tmp_path):
    """A scan surface holding one shaped leak per rule, plus exemption lines."""
    root = tmp_path / "leakroot"
    root.mkdir()
    body = ["# synthetic analysis notes"] + [line for _rule, line in LEAK_LINES]
    (root / "notes.md").write_text("\n".join(body) + "\n", encoding="utf-8")
    (root / "exempt.md").write_text("\n".join(line for _cls, line in EXEMPT_LINES) + "\n",
                                    encoding="utf-8")
    nested = root / "skills" / "exe-reverse" / "references"
    nested.mkdir(parents=True)
    (nested / "deep.md").write_text("no identity here\n", encoding="utf-8")
    return root


@pytest.fixture
def clean_scan_root(tmp_path):
    """A scan surface with nothing to report."""
    root = tmp_path / "clean"
    root.mkdir()
    (root / "notes.md").write_text(
        "Static PE analysis of the generated fixture: sections, imports, checksum.\n",
        encoding="utf-8")
    return root


@pytest.fixture
def platform_binary(require_local_tool):
    """A real platform image to parse, or a skip when this host has none."""
    root = os.environ.get("SystemRoot", r"C:\Windows")
    for rel in (r"System32\notepad.exe", r"System32\kernel32.dll", r"System32\ntdll.dll"):
        candidate = pathlib.Path(root) / rel
        if candidate.is_file():
            return candidate
    pytest.skip("no platform image under %s (System32 not present); this check is inert here"
                % root)
