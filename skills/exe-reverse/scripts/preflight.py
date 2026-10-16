#!/usr/bin/env python3
"""capability: host_capability_probe

Pre-flight for one analysis session: is this experiment ready to start, and what will it cost?

WHY THIS IS SEPARATE FROM `doctor.py`
-------------------------------------
`doctor.py` answers a question about the **machine**: which capabilities exist here, what is
missing, and which host facts would poison an experiment in general. This script answers a
question about a **session**: given the sample in front of you and the route you intend to take,
is everything in place, and is there room to store what the route produces?

The distinction is not cosmetic. The failures this catches are the ones that appear twenty minutes
in: a recording that fills the disk, an output path that overwrites the previous run's evidence, a
sample whose hash was never taken so the result cannot be attributed to a specific input, or a
debug route that cannot start because a virtualisation layer is intercepting the mechanism. Every
one of those is cheap to check now and expensive to discover later.

WHAT IT CHECKS
--------------
  * the sample: present, readable, hashed, and a working copy rather than the only copy;
  * the destination: exists or can be created, is writable, is not the input's own directory, and
    has the free space the chosen route needs;
  * the route: for the routes whose cost is not in the tool but in the prerequisites, whether the
    host meets them -- elevation, a hypervisor-free host, test-signed driver loading, a debugger;
  * interference: leftover tracing sessions and live debuggers that make a run incomparable.

WHAT IT DOES NOT DO
-------------------
It never launches the sample, never opens a debugger, and never writes to the sample. It creates
the output directory if asked to and nothing else.

Usage
-----
    python preflight.py --sample target.exe
    python preflight.py --sample target.exe --out work --route trace
    python preflight.py --sample target.exe --out work --route kernel --json
    python preflight.py --sample target.exe --list-routes

Exit codes: 0 = ready, 1 = ready with warnings, 3 = not ready, 2 = usage error.
The last line is `RESULT=<token>`.
"""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

EXIT_OK = 0
EXIT_WARN = 1
EXIT_USE = 2
EXIT_NOT_READY = 3

TOKENS = {'ready': 'preflight_ready', 'warn': 'preflight_ready_with_warnings',
          'not_ready': 'preflight_not_ready', 'use': 'usage_error'}

# Space a route needs beyond the sample itself. `basis` is the strength of the number: `observed`
# means this repository measured it, `unverified` means it is a planning aid. The point is not the
# figure's precision -- it is that a route with a large figure gets checked before it fills a disk,
# because the failure mode is a truncated recording that looks like a short one.
ROUTES = {
    'static': {
        'name': 'static analysis only',
        'needs_free_bytes': 64 * 1024 * 1024,
        'basis': 'observed',
        'why': 'text output, a patched copy, and a record. Measured: this repository\'s own scripts '
               'produced under 1 MB of output for a 31 MB target.',
        'requires': [],
    },
    'debug': {
        'name': 'interactive or command-line debugging',
        'needs_free_bytes': 256 * 1024 * 1024,
        'basis': 'unverified',
        'why': 'a dump taken mid-session is proportional to the process, and logs grow with the '
               'session length.',
        'requires': ['debugger'],
    },
    'dump': {
        'name': 'capture a process image',
        'needs_free_bytes': 4 * 1024 * 1024 * 1024,
        'basis': 'unverified',
        'why': 'a full dump of a large process plus a repaired copy beside it. Treat this as a '
               'floor, not an estimate.',
        'requires': ['debugger'],
    },
    'trace': {
        'name': 'record a session for replay',
        'needs_free_bytes': 16 * 1024 * 1024 * 1024,
        'basis': 'unverified',
        'why': 'a replay recording is proportional to instructions executed and to the process\'s '
               'memory, and it is the largest artefact any route here produces. Establish the '
               'figure on a short run before recording a long one.',
        'requires': ['replay-recorder', 'elevation'],
    },
    'kernel': {
        'name': 'kernel-level observation',
        'needs_free_bytes': 2 * 1024 * 1024 * 1024,
        'basis': 'unverified',
        'why': 'kernel debug output, driver builds, and the artefacts of a restart cycle.',
        'requires': ['elevation', 'no-hypervisor', 'test-signing'],
    },
}


def run(cmd, timeout=20):
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout, encoding='utf-8',
                           errors='replace')
        return p.returncode, (p.stdout or '') + (p.stderr or '')
    except (OSError, subprocess.SubprocessError) as exc:
        return -1, str(exc)


def sha256_of(path, chunk=1 << 20):
    h = hashlib.sha256()
    with open(path, 'rb') as fh:
        while True:
            b = fh.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


class Check(object):
    """One finding, with the severity that decides the exit code."""

    def __init__(self, area, ok, detail, severity='block', fix=''):
        self.area = area
        self.ok = ok
        self.detail = detail
        self.severity = severity          # block | warn | note
        self.fix = fix

    def as_dict(self):
        return {'area': self.area, 'ok': self.ok, 'detail': self.detail,
                'severity': self.severity, 'fix': self.fix}


def check_sample(path, out_dir):
    checks = []
    if not path:
        return checks
    if not os.path.isfile(path):
        checks.append(Check('sample', False, '%s is not a file' % path,
                            fix='give the path to the sample you intend to analyse'))
        return checks
    size = os.path.getsize(path)
    digest = sha256_of(path)
    checks.append(Check('sample', True, '%s, %d bytes, sha256 %s' % (path, size, digest[:16]),
                        severity='note'))
    checks.append(Check('sample', True,
                        'record this hash with every result: a conclusion is about these bytes',
                        severity='note'))
    writable = os.access(path, os.W_OK)
    if writable:
        checks.append(Check('sample', False,
                            'the sample is writable, so it can be modified in place by accident',
                            severity='warn',
                            fix='work on a copy: this kit\'s patcher writes a new file, but a '
                                'debugger or a tool you did not write may not'))
    else:
        checks.append(Check('sample', True, 'the sample is not writable (a good default)',
                            severity='note'))
    if out_dir:
        same = os.path.abspath(os.path.dirname(os.path.abspath(path))) == \
            os.path.abspath(out_dir)
        if same:
            checks.append(Check('sample', False,
                                'the output directory is the sample\'s own directory',
                                severity='warn',
                                fix='write outputs elsewhere: an output beside an input of the same '
                                    'name is how the wrong file gets analysed next'))
    return checks


def check_destination(out_dir, route):
    checks = []
    if not out_dir:
        return checks
    spec = ROUTES[route]
    abs_out = os.path.abspath(out_dir)
    if not os.path.isdir(abs_out):
        parent = os.path.dirname(abs_out) or '.'
        if not os.path.isdir(parent):
            checks.append(Check('destination', False,
                                '%s does not exist and neither does %s' % (abs_out, parent),
                                fix='create the parent, or name a directory that exists'))
            return checks
        try:
            os.makedirs(abs_out, exist_ok=True)
            checks.append(Check('destination', True, 'created %s' % abs_out, severity='note'))
        except OSError as exc:
            checks.append(Check('destination', False, 'could not create %s: %s' % (abs_out, exc),
                                fix='choose a path you can write to'))
            return checks
    if not os.access(abs_out, os.W_OK):
        checks.append(Check('destination', False, '%s is not writable' % abs_out,
                            fix='choose a writable path'))
        return checks

    try:
        usage = shutil.disk_usage(abs_out)
        need = spec['needs_free_bytes']
        if usage.free < need:
            checks.append(Check('destination', False,
                                'route "%s" needs about %.1f GB free; %.1f GB available'
                                % (route, need / 2**30, usage.free / 2**30),
                                fix='free space, choose another destination, or pick a cheaper '
                                    'route. A recording truncated by a full disk looks like a '
                                    'short one'))
        else:
            checks.append(Check('destination', True,
                                'route "%s" needs about %.1f GB; %.1f GB free (%s)'
                                % (route, need / 2**30, usage.free / 2**30, spec['basis']),
                                severity='note'))
    except OSError as exc:
        checks.append(Check('destination', True, 'free space unreadable: %s' % exc,
                            severity='warn'))
    return checks


def check_requirements(route, probe):
    """The route's prerequisites, from the same probe the rest of the kit uses."""
    checks = []
    spec = ROUTES[route]
    for req in spec['requires']:
        if req == 'elevation':
            v = probe._host_flag('elevation')
            checks.append(Check('route', bool(v),
                                'elevation: %s' % ('held' if v else 'not held'),
                                severity='note' if v else 'block',
                                fix='' if v else 'start an elevated shell; a script cannot raise '
                                                 'its own privilege'))
        elif req == 'no-hypervisor':
            v = probe._host_flag('hypervisor')
            checks.append(Check('route', bool(v),
                                'no virtualisation layer under this host: %s'
                                % ('yes' if v else 'no, one reports itself'),
                                severity='note' if v else 'block',
                                fix='' if v else 'the interception this route depends on may be '
                                                 'consumed by the layer. Move to a host without it, '
                                                 'or accept the route may not fire'))
        elif req == 'test-signing':
            v = probe._host_flag('test_signing')
            checks.append(Check('route', bool(v),
                                'test signing: %s' % ('enabled' if v else 'not enabled'),
                                severity='note' if v else 'block',
                                fix='' if v else 'bcdedit /set testsigning on, then reboot; a policy '
                                                 'may still refuse the driver'))
        elif req == 'debugger':
            found = [t for t in ('cdb', 'windbg', 'x64dbg', 'gdb') if probe.which(t)[0]]
            checks.append(Check('route', bool(found),
                                'debugger: %s' % (', '.join(found) if found else 'none found'),
                                severity='note' if found else 'block',
                                fix='' if found else 'install the debugging tools for Windows, or '
                                                     'route this question through a capability that '
                                                     'is available'))
        elif req == 'replay-recorder':
            found = [t for t in ('ttd', 'TTD') if probe.which(t)[0]]
            checks.append(Check('route', bool(found),
                                'replay recorder: %s' % ('present' if found else 'not found'),
                                severity='note' if found else 'block',
                                fix='' if found else 'it ships with the modern debugger package'))
    return checks


def check_interference(probe):
    checks = []
    if probe.which('logman')[0]:
        rc, out = run(['logman', 'query', '-ets'], timeout=20)
        if rc == 0:
            sessions = [ln for ln in out.splitlines()
                        if ln.strip() and 'Data Collector Set' not in ln and '---' not in ln
                        and not ln.startswith(' The ')]
            checks.append(Check('interference', True,
                                '%d tracing session(s) currently active (most are part of a normal '
                                'Windows boot)' % len(sessions), severity='note'))
    for t in ('x64dbg', 'x32dbg', 'windbg', 'cdb'):
        path, _via = probe.which(t)
        if path:
            checks.append(Check('interference', True,
                                '%s is installed at %s' % (t, path), severity='note'))
            break

    proxy = [v for v in ('HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy')
             if os.environ.get(v)]
    if proxy:
        checks.append(Check('interference', False,
                            '%s set: any capture through it describes the proxy hop' % proxy[0],
                            severity='warn',
                            fix='unset it for this session, or state in the record that the '
                                'observation went through it'))
    return checks


def main():
    ap = argparse.ArgumentParser(
        description='Is this analysis session ready to start, and is there room for what it '
                    'will produce?')
    ap.add_argument('--sample', help='the file about to be analysed')
    ap.add_argument('--out', help='the directory this session will write to')
    ap.add_argument('--route', default='static', choices=sorted(ROUTES),
                    help='the route you intend to take (default: static)')
    ap.add_argument('--list-routes', action='store_true', help='what each route costs and needs')
    ap.add_argument('--json', action='store_true')
    args = ap.parse_args()

    if args.list_routes:
        for key in sorted(ROUTES):
            spec = ROUTES[key]
            print('  %-8s %-40s ~%.1f GB  needs: %s'
                  % (key, spec['name'], spec['needs_free_bytes'] / 2**30,
                     ', '.join(spec['requires']) or 'nothing beyond the machine'))
            print('           %s' % spec['why'])
        print('\nRESULT=%s' % TOKENS['ready'])
        return EXIT_OK

    if not args.sample and not args.out:
        sys.stderr.write('error: give --sample, --out, or both\n')
        print('RESULT=%s' % TOKENS['use'])
        return EXIT_USE

    import capabilities as caps
    probe = caps.Probe()

    checks = []
    checks.extend(check_sample(args.sample, args.out))
    checks.extend(check_destination(args.out, args.route))
    checks.extend(check_requirements(args.route, probe))
    checks.extend(check_interference(probe))

    blocks = [c for c in checks if not c.ok and c.severity == 'block']
    warns = [c for c in checks if not c.ok and c.severity == 'warn']
    if blocks:
        token, code = TOKENS['not_ready'], EXIT_NOT_READY
    elif warns:
        token, code = TOKENS['warn'], EXIT_WARN
    else:
        token, code = TOKENS['ready'], EXIT_OK

    if args.json:
        print(json.dumps({'route': args.route, 'route_name': ROUTES[args.route]['name'],
                          'checks': [c.as_dict() for c in checks],
                          'blocks': len(blocks), 'warnings': len(warns),
                          'result': token}, indent=2))
        print('RESULT=%s' % token)
        return code

    print('pre-flight -- route: %s (%s)' % (args.route, ROUTES[args.route]['name']))
    print('  %s' % ROUTES[args.route]['why'])
    print()
    for c in checks:
        mark = 'ok  ' if c.ok else ('WARN' if c.severity == 'warn' else 'STOP')
        print('  %s %-12s %s' % (mark, c.area, c.detail))
        if not c.ok and c.fix:
            print('       %s' % c.fix)
    print()
    print('  %d blocking, %d warning(s)' % (len(blocks), len(warns)))
    print('  This is a statement about the session, not about the target.')
    print('RESULT=%s' % token)
    return code


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(EXIT_USE)
