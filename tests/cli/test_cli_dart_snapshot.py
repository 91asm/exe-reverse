"""Subprocess contract tests for skills/exe-reverse/scripts/dart_snapshot_strings.py.

The input is the generated ELF64 from `conftest.build_synthetic_elf`, never a sample: a valid
container with one one-byte literal, one two-byte literal and a `.text` that carries neither of the
idioms the pool observer counts.

Two conventions are pinned because they are not what the docstring's exit-code table suggests:

* `--json` returns 0 whatever the filter did, while the text mode returns 1 for "nothing matched";
* `--at` widens a match by `offset + len(text)`, and for a two-byte literal that is half the bytes
  the literal occupies, so an offset inside the literal's second half is reported as a miss.
"""
import json

import pytest

pytestmark = pytest.mark.cli


def plain_lines(text):
    return [line for line in text.splitlines() if line.strip()]


def reported_count(text):
    """The `N literal(s) reported.` line the text view ends with."""
    for line in reversed(plain_lines(text)):
        if "literal(s) reported." in line:
            return int(line.split()[0])
    raise AssertionError("no 'literal(s) reported.' line in:\n%s" % text)


# --- refusals ----------------------------------------------------------------

def test_a_file_that_is_not_an_elf_is_refused_with_the_documented_code(run_script, tmp_path):
    path = tmp_path / "notes.txt"
    path.write_text("this is not a snapshot\n", encoding="utf-8")
    result = run_script("dart_snapshot_strings.py", path)
    assert result.returncode == 3
    assert "not an ELF image" in result.stderr
    assert "Traceback" not in result.stderr
    assert result.stdout == ""


def test_a_truncated_image_is_refused_without_a_traceback(run_script, synthetic_elf, tmp_path):
    path = tmp_path / "truncated.so"
    path.write_bytes(synthetic_elf.data[:0x30])
    result = run_script("dart_snapshot_strings.py", path)
    assert result.returncode == 3
    assert "not an ELF image" in result.stderr
    assert "Traceback" not in result.stderr


def test_a_missing_file_exits_two_with_a_reason(run_script, tmp_path):
    result = run_script("dart_snapshot_strings.py", tmp_path / "absent.so")
    assert result.returncode == 2
    assert "error:" in result.stderr
    assert "Traceback" not in result.stderr


def test_an_elf_with_no_code_section_is_refused(run_script, synthetic_elf_without_text):
    """A shared object without `.text` is not an AOT code image, and the reader says so."""
    result = run_script("dart_snapshot_strings.py", synthetic_elf_without_text.path)
    assert result.returncode == 3
    assert "no .text section" in result.stderr
    assert "Traceback" not in result.stderr


# --- recovery ----------------------------------------------------------------

def test_the_default_run_reports_every_literal_it_recovered(run_script, synthetic_elf):
    result = run_script("dart_snapshot_strings.py", synthetic_elf.path)
    assert result.returncode == 0, result.stderr
    assert "x86-64, shared-object" in result.stdout
    for entry in synthetic_elf.literals:
        assert hex(entry["vaddr"]) in result.stdout
        assert entry["text"] in result.stdout
    assert "literals recovered  : 3" in result.stdout
    assert reported_count(result.stdout) == 3


def test_the_reference_mechanism_is_reported_as_counts_and_a_note(run_script, synthetic_elf):
    """Zero and zero on a generated image, with the note that explains what a real one looks like."""
    result = run_script("dart_snapshot_strings.py", synthetic_elf.path)
    assert "reference mechanism : 0 pool load(s) through r15, 0 self-relative load(s)" \
        in result.stdout
    assert "0 of the self-relative loads land in .rodata" in result.stdout
    assert "object pool" in result.stdout


def test_no_observe_skips_the_second_pass(run_script, synthetic_elf):
    result = run_script("dart_snapshot_strings.py", synthetic_elf.path, "--no-observe")
    assert result.returncode == 0, result.stderr
    assert "reference mechanism" not in result.stdout
    assert reported_count(result.stdout) == 3


def test_min_length_filters_the_short_literals_out(run_script, synthetic_elf):
    result = run_script("dart_snapshot_strings.py", synthetic_elf.path, "--min-length", "12")
    assert result.returncode == 0, result.stderr
    assert reported_count(result.stdout) == 1
    assert "premium_license" in result.stdout
    assert "trial_mode" not in result.stdout
    assert ">= 12 chars" in result.stdout


def test_limit_caps_how_many_are_reported(run_script, synthetic_elf):
    result = run_script("dart_snapshot_strings.py", synthetic_elf.path, "--limit", "1")
    assert result.returncode == 0, result.stderr
    assert reported_count(result.stdout) == 1


def test_section_selection_is_honoured(run_script, synthetic_elf):
    only_rodata = run_script("dart_snapshot_strings.py", synthetic_elf.path,
                             "--sections", ".rodata")
    assert only_rodata.returncode == 0, only_rodata.stderr
    assert reported_count(only_rodata.stdout) == 3

    only_text = run_script("dart_snapshot_strings.py", synthetic_elf.path, "--sections", ".text")
    assert only_text.returncode == 1
    assert reported_count(only_text.stdout) == 0

    absent = run_script("dart_snapshot_strings.py", synthetic_elf.path, "--sections", ".absent")
    assert absent.returncode == 1
    assert reported_count(absent.stdout) == 0


# --- keyword filter ----------------------------------------------------------

def test_find_matches_case_insensitively(run_script, synthetic_elf):
    lower = run_script("dart_snapshot_strings.py", synthetic_elf.path, "--find", "premium")
    upper = run_script("dart_snapshot_strings.py", synthetic_elf.path, "--find", "PREMIUM")
    assert lower.returncode == 0, lower.stderr
    assert upper.returncode == 0, upper.stderr
    assert reported_count(lower.stdout) == reported_count(upper.stdout) == 1
    assert "premium_license" in lower.stdout
    assert "trial_mode" not in lower.stdout


def test_find_accepts_a_comma_separated_list(run_script, synthetic_elf):
    result = run_script("dart_snapshot_strings.py", synthetic_elf.path, "--find", "trial, VIP")
    assert result.returncode == 0, result.stderr
    assert reported_count(result.stdout) == 2
    assert "trial_mode" in result.stdout
    assert "vip_pass" in result.stdout
    assert "premium_license" not in result.stdout


def test_find_can_reach_a_two_byte_literal(run_script, synthetic_elf):
    """A keyword search that only read ASCII would miss this one, which is why both are recovered."""
    result = run_script("dart_snapshot_strings.py", synthetic_elf.path, "--find", "vip")
    assert result.returncode == 0, result.stderr
    assert reported_count(result.stdout) == 1
    assert "[two-byte]" in result.stdout


def test_a_keyword_that_matches_nothing_changes_the_exit_code(run_script, synthetic_elf):
    """A miss is a negative finding, not an empty success."""
    result = run_script("dart_snapshot_strings.py", synthetic_elf.path, "--find", "no_such_keyword")
    assert result.returncode == 1
    assert reported_count(result.stdout) == 0
    assert "Traceback" not in result.stderr


# --- --at --------------------------------------------------------------------

def test_at_resolves_a_literal_by_file_offset(run_script, synthetic_elf):
    entry = synthetic_elf.literal("premium_license")
    result = run_script("dart_snapshot_strings.py", synthetic_elf.path, "--at", str(entry["offset"]))
    assert result.returncode == 0, result.stderr
    assert reported_count(result.stdout) == 1
    assert "premium_license" in result.stdout


def test_at_resolves_a_two_byte_literal_by_file_offset(run_script, synthetic_elf):
    entry = synthetic_elf.literal("vip_pass")
    result = run_script("dart_snapshot_strings.py", synthetic_elf.path, "--at", str(entry["offset"]))
    assert result.returncode == 0, result.stderr
    assert reported_count(result.stdout) == 1
    assert "vip_pass" in result.stdout


def test_at_resolves_a_literal_by_virtual_address(run_script, synthetic_elf):
    """The vaddr is far above the file size, which is how the reader tells the two apart."""
    entry = synthetic_elf.literal("vip_pass")
    assert entry["vaddr"] > synthetic_elf.size
    result = run_script("dart_snapshot_strings.py", synthetic_elf.path, "--at", hex(entry["vaddr"]))
    assert result.returncode == 0, result.stderr
    assert reported_count(result.stdout) == 1
    assert "vip_pass" in result.stdout
    assert hex(entry["vaddr"]) in result.stdout


def test_at_inside_the_code_section_matches_nothing(run_script, synthetic_elf):
    result = run_script("dart_snapshot_strings.py", synthetic_elf.path, "--at",
                        str(synthetic_elf.text["offset"] + 1))
    assert result.returncode == 1
    assert reported_count(result.stdout) == 0


def test_at_misses_the_second_half_of_a_two_byte_literal(load_script, run_script, synthetic_elf):
    """Pinned deviation, measured rather than assumed.

    `--at` keeps a literal when `offset <= at < offset + len(text)`. For a two-byte literal the
    offsets are bytes and the text is characters, so the window covers the first eight of the
    sixteen bytes the literal occupies: a real byte offset inside the literal is reported as a miss.
    The same expression is correct for a one-byte literal, where the two units agree.
    """
    entry = synthetic_elf.literal("vip_pass")
    assert entry["encoding"] == "two-byte"
    inside_but_past_the_window = entry["offset"] + len(entry["text"])
    inside_the_literal = entry["offset"] + 2 * (len(entry["text"]) - 1)
    assert entry["offset"] < inside_but_past_the_window < inside_the_literal

    missed = run_script("dart_snapshot_strings.py", synthetic_elf.path, "--at",
                        str(inside_but_past_the_window))
    assert missed.returncode == 1
    assert reported_count(missed.stdout) == 0

    # The bytes really are there: the offset the CLI calls a miss is inside the literal.
    assert synthetic_elf.data[inside_but_past_the_window] in range(0x20, 0x7F)

    recovered = load_script("dart_snapshot_strings.py").recover_strings(
        synthetic_elf.data, {"offset": synthetic_elf.rodata["offset"],
                             "vaddr": synthetic_elf.rodata["vaddr"],
                             "size": synthetic_elf.rodata["size"]})
    matched = [row for row in recovered
               if row[0] <= inside_but_past_the_window < row[0] + 2 * len(row[2])]
    assert [row[2] for row in matched] == ["vip_pass"]


def test_at_can_be_combined_with_find(run_script, synthetic_elf):
    entry = synthetic_elf.literal("trial_mode")
    hit = run_script("dart_snapshot_strings.py", synthetic_elf.path, "--find", "trial",
                     "--at", str(entry["offset"]))
    assert hit.returncode == 0, hit.stderr
    assert reported_count(hit.stdout) == 1

    miss = run_script("dart_snapshot_strings.py", synthetic_elf.path, "--find", "premium",
                      "--at", str(entry["offset"]))
    assert miss.returncode == 1
    assert reported_count(miss.stdout) == 0


# --- json --------------------------------------------------------------------

def test_json_carries_the_matches_and_the_pool_observation(run_script, synthetic_elf):
    result = run_script("dart_snapshot_strings.py", synthetic_elf.path, "--json")
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)          # the whole stream: this mode prints no RESULT line
    assert payload["image"] == str(synthetic_elf.path)
    assert payload["elf"]["machine"] == "x86-64"
    assert payload["elf"]["type"] == "shared-object"
    assert payload["literals_recovered"] == 3
    assert [entry["text"] for entry in payload["matches"]] == \
        [entry["text"] for entry in synthetic_elf.literals]
    for entry, fixture in zip(payload["matches"], synthetic_elf.literals):
        assert entry["offset"] == hex(fixture["offset"])
        assert entry["vaddr"] == hex(fixture["vaddr"])
        assert entry["encoding"] == fixture["encoding"]
    observation = payload["pool_observation"]
    assert observation["pool_loads_r15"] == 0
    assert observation["self_relative_loads"] == 0
    assert "note" in observation


def test_json_with_no_observe_reports_no_observation(run_script, synthetic_elf):
    result = run_script("dart_snapshot_strings.py", synthetic_elf.path, "--json", "--no-observe")
    payload = json.loads(result.stdout)
    assert payload["pool_observation"] is None
    assert payload["literals_recovered"] == 3


def test_json_returns_zero_even_when_the_filter_matched_nothing(run_script, synthetic_elf):
    """Pinned deviation: the text mode returns 1 for a miss, the JSON mode returns 0 for the same
    filter. A caller that reads only the exit code cannot tell the two apart."""
    text_mode = run_script("dart_snapshot_strings.py", synthetic_elf.path, "--find", "no_such_word")
    json_mode = run_script("dart_snapshot_strings.py", synthetic_elf.path, "--find", "no_such_word",
                           "--json")
    assert text_mode.returncode == 1
    assert json_mode.returncode == 0
    payload = json.loads(json_mode.stdout)
    assert payload["matches"] == []
    assert payload["literals_recovered"] == 0


def test_an_unknown_flag_is_a_usage_error(run_script):
    result = run_script("dart_snapshot_strings.py", "--definitely-not-a-flag")
    assert result.returncode == 2
    assert "usage:" in result.stderr.lower()
    assert "Traceback" not in result.stderr


def test_help_exits_zero(run_script):
    result = run_script("dart_snapshot_strings.py", "--help")
    assert result.returncode == 0
    assert "usage:" in result.stdout.lower()
    assert "app.so" in result.stdout
