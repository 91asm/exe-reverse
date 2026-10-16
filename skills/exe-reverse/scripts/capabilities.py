#!/usr/bin/env python3
"""The capability registry this skill's metadata points at: what each route needs, and whether
this host has it.

Why a registry rather than a list in prose: every route in this skill is conditional. Hardware
breakpoints need four debug registers and a host where the debug exception is not intercepted;
instruction tracing needs a processor feature *and* a capture path; a kernel driver needs test
signing and a reboot; managed assemblies need tooling that is not a hex editor; ETW needs an
elevated session. A route that is planned without checking its precondition fails at the first
step and the failure gets attributed to the target. So each capability here states what it needs,
how to detect whether this machine has it, which script implements it, and which reference
documents it -- and the detection is a real probe, not an assumption.

Three states, and they are not interchangeable:

  available    -- measured to work on this machine right now
  needs-<x>    -- the mechanism exists but is gated on something named in the row
  unavailable  -- measured absent
  unknown      -- the probe itself could not run, so nothing is claimed about this machine

`unknown` is separate from `unavailable` on purpose, and the distinction is this skill's rule:
"the probe could not read CPUID" and "this CPU lacks the feature" are different statements, and
collapsing them turns a broken measurement into a fact. A missing capability is a finding about
the machine, not a failure of the task, so the exit code never reflects it.

This module imports cleanly with no side effects and no third-party imports: the table is data,
and every probe is behind `--check`. Probing reuses `hwprobe.py` rather than reimplementing it --
CPUID, the OS and policy keys, the privilege token, the tool inventory and the Python module list
all come from that script's own functions, so this registry cannot drift away from the probe it
describes. The one join it cannot read directly is the tool *name* for a found path: hwprobe's
tool rows carry the reason and the resolved path but not the name, so the index here is built from
the resolved basename and a name that resolves to something unexpected will show as missing rather
than as present.

A note on the reference column: this registry names only reference files that exist in this
checkout. Where the route is documented in this skill by a file that is not present, the row says
so in its boundary rather than pointing a reader at a path that will not open.

Usage:
    python capabilities.py --list
    python capabilities.py --check
    python capabilities.py --check --json
    python capabilities.py --explain pe-build-compare

Exit codes: 0 = report produced, 2 = usage error, 3 = --explain named an unknown capability id.
"""
import argparse
import json
import os
import platform
import sys

# --- registry -----------------------------------------------------------------
# detect is (kind, argument). The kinds are implemented by capability_state() below; anything not
# in that table is reported as unknown rather than guessed, so adding a row cannot silently produce
# a wrong answer.
CAPABILITIES = [
    {
        'id': 'pe-structure-read',
        'what': 'parse PE headers, sections, directories and translate an RVA to a file offset',
        'needs': 'Python 3.9+ and read access to the file',
        'needs_short': 'python',
        'detect': ('python', None),
        'script': 'peutil.py',
        'reference': 'references/pe-structure.md',
        'boundary': ('reads headers and structures; it does not disassemble, decompile or repair a '
                     'damaged image'),
    },
    {
        'id': 'pe-triage-signals',
        'what': 'one-pass triage of an unknown PE: identity, build evidence, protective signals',
        'needs': 'Python 3.9+ and read access to the file',
        'needs_short': 'python',
        'detect': ('python', None),
        'script': 'pe_triage.py',
        'reference': 'references/recon.md',
        'boundary': ('header-level heuristics. Entropy, section shape and a thin import table are '
                     'reasons to look, never verdicts, and this route cannot establish that an '
                     'image is packed'),
    },
    {
        'id': 'pe-checksum-recompute',
        'what': 'compute the PE checksum Microsoft\'s own algorithm produces, and compare it',
        'needs': 'Python 3.9+; cost is linear in file size',
        'needs_short': 'python',
        'detect': ('python', None),
        'script': 'peutil.py',
        'reference': 'references/integrity-checks.md',
        'boundary': ('the PE checksum only. It says nothing about an Authenticode signature, and a '
                     'matching checksum is not evidence that the file was not modified'),
    },
    {
        'id': 'equal-length-byte-patch',
        'what': 'apply an equal-length, verified byte patch and recompute the checksum',
        'needs': 'Python 3.9+ and a writable copy of the input',
        'needs_short': 'python + writable copy',
        'detect': ('python', None),
        'script': 'pepatch.py',
        'reference': 'references/patching.md',
        'boundary': ('equal-length edits only unless a resize is explicitly requested; a patch that '
                     'lands in the file is still not proof it is reached at run time'),
    },
    {
        'id': 'aob-signature-locate',
        'what': 'locate a byte pattern and report how many sites it matches',
        'needs': 'Python 3.9+ and read access to the file',
        'needs_short': 'python',
        'detect': ('python', None),
        'script': 'aob_scan.py',
        'reference': 'references/aob-and-signatures.md',
        'boundary': ('a pattern is a locator only while it is unique; this route reports ambiguity '
                     'rather than picking the first hit'),
    },
    {
        'id': 'pe-build-compare',
        'what': 'compare two builds: section content hashes, normalised volatile fields, byte ranges',
        'needs': 'Python 3.9+ and both files on disk',
        'needs_short': 'python + two builds',
        'detect': ('python', None),
        'script': 'pe_diff.py',
        'reference': 'references/verification.md',
        'boundary': ('a diff shows change, never intent, and identical bytes do not prove identical '
                     'behaviour'),
    },
    {
        'id': 'fixture-pe-generation',
        'what': 'build a deterministic synthetic PE to test a parser or a patch offline',
        'needs': 'Python 3.9+',
        'needs_short': 'python',
        'detect': ('python', None),
        'script': 'make_fixture_pe.py',
        'reference': 'references/verification.md',
        'boundary': ('structurally valid but not runnable: there is no real code and the entry '
                     'point is a stub, so it cannot verify behaviour'),
    },
    {
        'id': 'leak-scan-before-publish',
        'what': 'scan notes and scripts for target identity before they leave the machine',
        'needs': 'Python 3.9+',
        'needs_short': 'python',
        'detect': ('python', None),
        'script': 'scan_leaks.py',
        'reference': 'references/desensitization.md',
        'boundary': ('a rule table over text; it cannot recognise an identifier it has no rule for'),
    },
    {
        'id': 'host-capability-probe',
        'what': 'measure what this machine supports, with the probe behind every answer',
        'needs': 'Python 3.9+; the CPUID stub needs a Windows x64 host to allocate and call',
        'needs_short': 'python on Windows',
        'detect': ('python', None),
        'script': 'hwprobe.py',
        'reference': 'references/environment.md',
        'boundary': ('reports measurements, not a plan; CPUID capability bits whose meanings were '
                     'not verified against a primary source are printed raw'),
    },
    {
        'id': 'interactive-user-debugger',
        'what': 'attach, break, single-step and inspect a live process',
        'needs': 'a debugger installed (x64dbg, WinDbg or cdb)',
        'needs_short': 'a debugger',
        'detect': ('tool', ('x64dbg', 'windbg', 'cdb')),
        'script': None,
        'reference': 'references/dynamic-debugging.md',
        'boundary': ('interactive: a GUI debugger is run by a person, not shelled by these scripts. '
                     'A target that detects the debugger fails this route before it yields data'),
    },
    {
        'id': 'hardware-breakpoints',
        'what': 'watch an address or an access through the processor debug registers (DR0-DR3)',
        'needs': 'a user-mode debugger and a host where the debug exception is not intercepted',
        'needs_short': '4 debug registers',
        'detect': ('cpu', 'hypervisor'),
        'state_map': {True: 'needs-hypervisor-free-host', False: 'available'},
        'script': 'hwprobe.py',
        'reference': 'references/dynamic-debugging.md',
        'boundary': ('four registers is an architectural constant; when a hypervisor is present the '
                     'debug exception may be intercepted rather than reaching your handler, which '
                     'is why the row is gated on it'),
    },
    {
        'id': 'instruction-trace-intel-pt',
        'what': 'capture a full instruction trace with no software instrumentation in the target',
        'needs': 'CPUID.07H.0:EBX[25] set, plus a capture path (ETW or a driver) and a decoder',
        'needs_short': 'CPU trace support',
        'detect': ('cpu', 'intel_pt'),
        'script': 'hwprobe.py',
        'reference': 'references/environment.md',
        'boundary': ('the CPU reporting support is not the same as capture working end to end. Treat '
                     'the capture path, not the feature bit, as the constraint; the dedicated '
                     'reference file for this route is not present in this checkout'),
    },
    {
        'id': 'etw-capture',
        'what': 'record system and provider events for offline correlation',
        'needs': 'wpr, xperf, logman or tracelog, and normally an elevated session',
        'needs_short': 'ETW tooling',
        'detect': ('tool', ('wpr', 'xperf', 'logman', 'tracelog')),
        'script': None,
        'reference': 'references/environment.md',
        'boundary': ('kernel providers need elevation; a trace is evidence about what the system '
                     'did, not about what the target intended'),
    },
    {
        'id': 'kernel-driver-load',
        'what': 'load and observe a driver of your own, or the target\'s',
        'needs': 'test signing or a kernel-debug boot flag, plus a reboot; VBS/HVCI may refuse an '
                 'unsigned driver regardless',
        'needs_short': 'test signing',
        'detect': ('boot', 'testsigning'),
        'script': 'hwprobe.py',
        'reference': 'references/environment.md',
        'boundary': ('no route around a driver signature is shipped here; the gate is reported, and '
                     'a second machine is usually cheaper than defeating it. The dedicated '
                     'reference file for this route is not present in this checkout'),
    },
    {
        'id': 'kernel-debug',
        'what': 'debug the kernel with a debugger attached over a debug transport',
        'needs': 'the kernel-debug boot flag and a second machine or a virtual serial pair',
        'needs_short': 'kernel debug boot',
        'detect': ('boot', 'kernel-debug-boot'),
        'script': 'hwprobe.py',
        'reference': 'references/environment.md',
        'boundary': ('the boot flag being present says the machine is configured for it, not that a '
                     'debugger is connected; a kernel debug of a live host on the same machine is '
                     'not offered here'),
    },
    {
        'id': 'runtime-instrumentation-frida',
        'what': 'hook and trace a running process from a script without touching the file',
        'needs': 'the frida Python module or the frida CLI',
        'needs_short': 'frida',
        'detect': ('module', 'frida'),
        'script': None,
        'reference': 'references/injection-and-hooking.md',
        'boundary': ('hooks are observable: a target that checks its own code, its import table or '
                     'its thread context can detect this route'),
    },
    {
        'id': 'memory-dump-analysis',
        'what': 'capture a process image and analyse what the live process actually contained',
        'needs': 'procdump or a debugger able to write a dump',
        'needs_short': 'a dumper',
        'detect': ('tool', ('procdump', 'windbg')),
        'script': None,
        'reference': 'references/memory-and-dumps.md',
        'boundary': ('a dump is a snapshot of one moment: code that was not yet unpacked or not yet '
                     'paged in is simply absent from it'),
    },
    {
        'id': 'time-travel-debugging',
        'what': 'record execution and replay it backwards to find the origin of a value',
        'needs': 'WinDbg with TTD support, and a process that may be recorded',
        'needs_short': 'windbg (TTD)',
        'detect': ('tool', ('windbg',)),
        'script': None,
        'reference': 'references/memory-and-dumps.md',
        'boundary': ('recording is user-mode only and heavy; a trace whose format you cannot replay '
                     'is not a finding'),
    },
    {
        'id': 'signature-inspection',
        'what': 'inspect and re-sign an Authenticode signature',
        'needs': 'signtool (MSVC/Windows SDK tooling)',
        'needs_short': 'signtool',
        'detect': ('tool', ('signtool',)),
        'script': None,
        'reference': 'references/integrity-checks.md',
        'boundary': ('inspecting a signature and producing one that a target accepts are different '
                     'problems; only the first is offered here'),
    },
    {
        'id': 'elevated-privilege',
        'what': 'act with an administrator token, which several routes above require',
        'needs': 'an elevated session',
        'needs_short': 'elevation',
        'detect': ('privilege', 'elevated'),
        'script': 'hwprobe.py',
        'reference': 'references/environment.md',
        'boundary': ('elevation is necessary for some routes and never sufficient for any: it does '
                     'not enable a driver load or a kernel debug on its own'),
    },
    {
        'id': 'licence-mechanism-classification',
        'what': 'classify where a licence decision is made before touching any code',
        'needs': 'Python 3.9+ (the classification itself is analysis, not a tool)',
        'needs_short': 'python',
        'detect': ('python', None),
        'script': None,
        'reference': 'references/license-mechanisms.md',
        'boundary': ('classifies the mechanism; a client-side patch cannot change a decision the '
                     'server makes, and misidentifying the owning layer is the most expensive wrong '
                     'turn in this skill'),
    },
]


def load_hwprobe():
    """(module, error). Imported lazily so that --list and --explain have no side effects."""
    here = os.path.dirname(os.path.abspath(__file__))
    if here not in sys.path:
        sys.path.insert(0, here)
    try:
        import hwprobe
        return hwprobe, None
    except Exception as exc:                      # pragma: no cover - depends on the checkout
        return None, '%s: %s' % (type(exc).__name__, exc)


def tool_index(hw):
    """{name: path} from hwprobe's tool rows.

    hwprobe.probe_tools() returns the reason and the resolved path per row but not the tool name,
    so the name is recovered from the basename. A tool that resolves to an unexpected file name is
    reported as missing rather than as present; that direction of error is the safe one, because a
    capability wrongly reported present is what sends a plan down a route the host cannot support.
    """
    index = {}
    for row in hw.probe_tools([]):
        if row.get('state') != 'available' or not row.get('value'):
            continue
        base = os.path.basename(str(row['value'])).lower()
        for ext in ('.exe', '.cmd', '.bat', '.py'):
            if base.endswith(ext):
                base = base[:-len(ext)]
                break
        index.setdefault(base, str(row['value']))
    return index


def probe_host():
    """Measure the facts the registry's detect rules read. Reuses hwprobe throughout."""
    facts = {
        'python': sys.version.split()[0],
        'platform': platform.platform(),
        'windows': platform.system() == 'Windows',
        'tools': {},
        'modules': {},
        'cpu': {'hypervisor': None, 'intel_pt': None, 'family_model': None, 'reason': None},
        'privilege': {'elevated': None},
        'os': {'build': None, 'boot_flags': [], 'device_guard': {}},
        'probe': {'available': False, 'reason': None},
    }
    hw, err = load_hwprobe()
    if hw is None:
        facts['probe']['reason'] = ('hwprobe.py could not be imported: %s' % err)
        return facts
    facts['probe'] = {'available': True, 'reason': None}

    facts['tools'] = tool_index(hw)
    for row in hw.python_modules():
        facts['modules'][str(row['value'])] = (row['state'] == 'available')

    for row in hw.probe_os():
        note = row.get('note') or ''
        if 'CurrentVersion registry' in note:
            facts['os']['build'] = row.get('value')
        elif note == 'SystemStartOptions boot flags':
            value = row.get('value')
            facts['os']['boot_flags'] = list(value) if isinstance(value, list) else []
        elif 'EnableVirtualizationBasedSecurity' in note:
            facts['os']['device_guard']['vbs'] = row.get('value')
        elif 'HypervisorEnforcedCodeIntegrity' in note:
            facts['os']['device_guard']['hvci'] = row.get('value')
        elif 'CredentialGuard' in note:
            facts['os']['device_guard']['credential_guard'] = row.get('value')

    for row in hw.probe_privilege():
        if 'TokenElevation' in (row.get('note') or ''):
            facts['privilege']['elevated'] = row.get('value')

    with hw.Cpuid() as cpuid:
        if not cpuid.available:
            facts['cpu']['reason'] = cpuid.reason
        else:
            rows, _raw = hw.probe_cpu(cpuid)
            for row in rows:
                note = row.get('note') or ''
                if 'ECX[31]' in note:
                    facts['cpu']['hypervisor'] = row.get('value')
                elif 'EBX[25]' in note:
                    facts['cpu']['intel_pt'] = row.get('value')
                elif note == 'CPUID.01H':
                    facts['cpu']['family_model'] = row.get('value')
    return facts


def capability_state(cap, facts):
    """(state, reason). Every state is derived from a measurement or reported as unknown."""
    kind, arg = cap['detect']
    if kind == 'python':
        return 'available', 'this interpreter: Python %s' % facts['python']
    if kind == 'windows':
        return (('available' if facts['windows'] else 'unavailable'),
                'platform.system() = %s' % platform.system())
    if kind == 'tool':
        hits = [t for t in arg if facts['tools'].get(t)]
        if hits:
            found = ', '.join('%s (%s)' % (h, facts['tools'][h]) for h in hits[:2])
            return 'available', 'found: %s' % found
        if not facts['probe']['available']:
            return 'unknown', facts['probe']['reason']
        if len(arg) == 1:
            return 'needs-%s' % arg[0], ('%s is not on PATH; the inventory behind this row is '
                                         'hwprobe.probe_tools()' % arg[0])
        return 'needs-%s' % arg[0], ('none of %s resolved on PATH; the inventory behind this row '
                                     'is hwprobe.probe_tools()' % ', '.join(arg))
    if kind == 'module':
        got = facts['modules'].get(arg)
        if not facts['probe']['available']:
            return 'unknown', facts['probe']['reason']
        if got is True:
            return 'available', 'importable: %s (hwprobe.python_modules)' % arg
        if got is False:
            return 'needs-%s' % arg, '%s is not importable on this interpreter' % arg
        return 'unknown', 'the module probe reported nothing for %s' % arg
    if kind == 'cpu':
        value = facts['cpu'].get(arg)
        if value is None:
            return 'unknown', (facts['cpu']['reason'] or 'the CPUID probe returned no value for %s'
                               % arg)
        if arg == 'intel_pt':
            measurement = 'CPUID.07H.0:EBX[25] = %d' % int(bool(value))
        else:
            measurement = 'CPUID.01H:ECX[31] = %d (a hypervisor is running this host)' \
                          % int(bool(value))
        state_map = cap.get('state_map')
        if state_map:
            return state_map[bool(value)], measurement
        return (('available' if value else 'unavailable')), measurement
    if kind == 'privilege':
        elevated = facts['privilege'].get('elevated')
        if elevated is None:
            return 'unknown', 'the token probe did not return an elevation state'
        state = 'available' if elevated else 'needs-elevation'
        return state, 'TokenElevation = %s, read through hwprobe' % bool(elevated)
    if kind == 'boot':
        flags = facts['os'].get('boot_flags') or []
        if arg in flags:
            return 'available', 'boot flag present: %s (SystemStartOptions)' % arg
        return 'needs-%s' % arg, ('boot flags: %s' % (', '.join(flags) or 'none')
                                  + '; a boot flag change needs a reboot')
    return 'unknown', 'no probe is implemented for detect kind %r' % (kind,)


def capability_rows(facts):
    rows = []
    for cap in CAPABILITIES:
        row = dict(cap)
        if facts is None:
            row['state'] = None
            row['state_reason'] = 'not probed (pass --check)'
        else:
            state, reason = capability_state(cap, facts)
            row['state'] = state
            row['state_reason'] = reason
        rows.append(row)
    return rows


def find_capability(cap_id):
    for cap in CAPABILITIES:
        if cap['id'] == cap_id:
            return cap
    return None


def print_table(rows):
    print('%-34s %-22s %-20s %s' % ('capability', 'needs', 'script', 'reference'))
    for row in rows:
        print('%-34s %-22s %-20s %s' % (row['id'], row['needs_short'], row['script'] or '-',
                                        row['reference']))
    print('\n%d capabilities. `--check` probes this host; `--explain <id>` gives one row in full.'
          % len(rows))


def print_check(rows):
    print('capability check on this host')
    width = max(len(r['id']) for r in rows)
    for row in rows:
        print('  %-*s  %-28s %s' % (width, row['id'], row['state'], row['script'] or '-'))
        print('  %-*s  %s' % (width, '', row['state_reason']))
    counts = {}
    for row in rows:
        key = row['state'] if row['state'] in ('available', 'unknown') else (
            'needs-something' if str(row['state']).startswith('needs-') else 'unavailable')
        counts[key] = counts.get(key, 0) + 1
    print('\n%d capabilities: %s' % (len(rows), ', '.join('%s=%d' % kv
                                                          for kv in sorted(counts.items()))))
    print('A capability this host lacks is a finding about the machine, not a failure of the task, '
          'and it never changes the exit code.')


def print_explain(cap):
    print('%s' % cap['id'])
    print('  what       : %s' % cap['what'])
    print('  needs      : %s' % cap['needs'])
    print('  detect     : %s' % describe_detect(cap['detect']))
    print('  script     : %s' % (cap['script'] or '(no script: this route is driven by a person or '
                                                  'external tooling)'))
    print('  reference  : %s' % cap['reference'])
    print('  boundary   : %s' % cap['boundary'])
    print('  host state : not measured here; run --check (this command has no side effects)')


def describe_detect(detect):
    kind, arg = detect
    if kind == 'python':
        return 'the interpreter running this script'
    if kind == 'tool':
        return 'any of %s resolved on PATH' % ', '.join(arg)
    if kind == 'module':
        return '%s importable by this interpreter' % arg
    if kind == 'cpu':
        return 'CPUID bit %s, read through hwprobe' % arg
    if kind == 'privilege':
        return 'the process token\'s elevation state, read through hwprobe'
    if kind == 'boot':
        return 'the %s boot flag in SystemStartOptions, read through hwprobe' % arg
    return 'no probe implemented'


def main():
    ap = argparse.ArgumentParser(
        description='The capability registry for this skill: what each route needs, how to detect '
                    'it here, and which script and reference cover it.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='Example:\n  python capabilities.py --check')
    ap.add_argument('--list', action='store_true', help='print the registry table')
    ap.add_argument('--check', action='store_true',
                    help='probe this host and report available / needs-x / unavailable / unknown')
    ap.add_argument('--explain', metavar='ID', help='one capability in full, including its boundary')
    ap.add_argument('--json', action='store_true', help='emit the registry as JSON')
    args = ap.parse_args()

    if not (args.list or args.check or args.explain or args.json):
        ap.error('choose one of --list, --check, --explain ID or --json')

    if args.explain and find_capability(args.explain) is None:
        sys.stderr.write('error: unknown capability id %r\n' % args.explain)
        sys.stderr.write('known ids: %s\n' % ', '.join(sorted(c['id'] for c in CAPABILITIES)))
        return 3

    facts = probe_host() if args.check else None
    rows = capability_rows(facts)

    if args.explain:
        if args.json:
            print(json.dumps(find_capability(args.explain), indent=2, ensure_ascii=True))
        else:
            print_explain(find_capability(args.explain))
        return 0

    if args.json:
        payload = {
            'python': sys.version.split()[0],
            'platform': platform.platform(),
            'probe': (facts['probe'] if facts else {'available': False,
                                                    'reason': 'not probed (no --check)'}),
            'host': ({'tools_found': len(facts['tools']),
                      'modules_available': sorted(m for m, ok in facts['modules'].items() if ok),
                      'cpu': facts['cpu'], 'privilege': facts['privilege'], 'os': facts['os']}
                     if facts else None),
            'capabilities': rows,
            'states': {r['id']: r['state'] for r in rows},
        }
        print(json.dumps(payload, indent=2, ensure_ascii=True))
        return 0

    if args.check:
        print_check(rows)
    else:
        print_table(rows)
    return 0


if __name__ == '__main__':
    sys.exit(main())
