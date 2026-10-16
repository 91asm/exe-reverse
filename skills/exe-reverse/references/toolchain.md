# The Toolchain: What to Install, What It Cannot Do, and How to Invoke It Unattended

Goal: know which tool owns which question, whether that tool can be driven from a script, and how to
find out what this machine actually has instead of assuming either a rich install or an empty one.

## When to load this

Load this when a documented command fails and the instinct is "the tool is missing", when a step needs
a capability whose tool you have not yet identified, when a run returns more output than you can read,
or when you are about to substitute a weaker method for a tool that turns out to be interactive or
GUI-only. The symptom index routes "a tool returns more output than you can read, or the same run
returns different amounts" and "a documented command does not run, or a tool is missing" here.

## The rule that decides every other question in this file

**A tool counts as installed when it runs and produces output — not when a file with its name exists
on `PATH`.** Three consequences, each of which has cost a session:

1. **A tool installed off `PATH` is not missing.** Installers place binaries in versioned directories,
   under a user profile, or inside an SDK tree, and nothing adds them to `PATH`. A probe that only
   consults `PATH` therefore reports a capable machine as bare. The host probe in this skill does the
   right thing: it resolves each name against `PATH` first and then against directories supplied
   through its own option and through an environment variable naming extra directories, and it labels
   a hit found that way so the reader can tell the two apart (`observed`, this skill's
   `scripts/hwprobe.py`).
2. **A runnable archive counts as installed.** A `.py` invoked through the interpreter, or a `.jar`
   invoked through the host's Java runtime, is a capability that exists. The test is the same as
   above: give it an input and see that it produces output. Only after that fails is it absent.
3. **A capability you never probed for is not a capability you lack.** The probe is cheap and it
   answers with three states rather than two — available, needs-something-named, and unavailable with
   the reason — because the hardware-assisted routes are conditional by nature (`observed`, the host
   probe's own contract). "Needs a restart and test signing" and "the CPU does not report this" are
   different findings and lead to different plans.

Two invocations, run in this order before any plan depends on a tool:

```
python scripts/hwprobe.py --tools      # which tools and Python modules this machine has
python scripts/hwprobe.py              # which routes those tools and this CPU can support
python scripts/hwprobe.py --json       # the same report, machine-readable
```

An inventory that comes back empty for a category is a finding to state out loud, with the search
that produced it, not a licence to reach for a weaker method silently.

## Categories: purpose, limit, scriptability

| Category | What it is for | What it cannot do | Driveable from a script |
|---|---|---|---|
| Static PE reader / header viewer | Read the headers, section table, imports, exports, directories and checksum of a file on disk | Say what any of it means; follow data flow; see anything that exists only at run time | Yes. The Microsoft toolchain's header dumper is a plain command (`dumpbin /headers <sample>`, `observed` from the compiler's option reference). This skill also ships a dependency-free reader (`scripts/peutil.py`, invoked as `python scripts/peutil.py <sample> --sections` and with flags for imports, exports, resources, TLS, relocations and entropy), measured here against real system images |
| Disassembler | Turn bytes into instructions, build a listing, find cross-references | Recover names, types or intent; produce correct output for data or for code it is told to start at the wrong boundary | Depends on the tool, and this split is the important one — see below |
| Decompiler | Turn a function into a pseudo-source form that is far quicker to read than assembly | Be trusted as a specification: optimisations, inlining and structure recovery make the output an approximation of the original source, not a copy of it | Depends on the tool; the ones with a scripting interface are scriptable, the GUI-only ones are not |
| Debugger | Control execution, place breakpoints, read registers and memory, inspect a dump | Replace the target's own logging for understanding intent; work at all against a target that refuses attachment | Two forms exist and they are not interchangeable — see below |
| Command-line debugger engine | The same engine as the interactive debugger, driven by an initial command string, usable unattended and over a dump | Anything requiring human judgement mid-session; it will sit waiting if a command asks it a question | Yes. The engine accepts a process id or a dump file and a quoted command list (`cdb -p <pid> -c "<commands>"`, `cdb -z <dumpfile> -c "<commands>"`, `observed` from the engine's option reference) |
| Interactive GUI debugger | Visual stepping, memory views, a human at the keyboard | Be scripted. Its buttons and panes are not a stable machine interface | No. Request it from the human operator instead of replacing it with a weaker method |
| Instrumentation framework | Inject an agent and run a script inside the live target: hook functions, read arguments, modify return values, iterate without rebuilding | Stay invisible; leave timing and memory layout unchanged; work when the target detects in-process agents | Yes, through its own scripting layer — which is the point of using one |
| Dump and repair tooling | Capture a process's address space, then turn a capture back into something loadable | Capture what was not there (uncommitted pages, kernel state) or repair a reconstruction whose header is gone | Partly. Capture is scriptable; repair is arithmetic you implement, using the section table as the map |
| Signature / packing identifier | Name the protector or packer from structural evidence, so the unpack route can be chosen | Unpack anything, or tell you the version-specific trick; an identification is a starting point, not a solution | Yes for the console form; the GUI form is not |
| Managed-code tooling | Disassemble, reassemble and inspect CIL, and query which runtimes are installed | Read native code, or be used instead of native tooling on a native binary | Yes. The .NET CLI answers for the installed runtimes on this host (`dotnet --list-runtimes`, `observed`), and the SDK's IL disassembler and assembler are ordinary commands |
| Kernel tooling | Enable test signing, configure kernel debugging, load and inspect drivers | Operate from user mode; load an unsigned driver while the platform's virtualisation-based integrity features are enforcing signature policy | Yes, but the effect needs a restart — the boot-configuration editor is a command (`bcdedit /set testsigning on`, `observed` from the boot-option reference), and the platform may still refuse the driver |
| Performance / ETW tooling | Collect a system-wide or process-scoped trace and turn it into a readable report: call activity, timings, stack samples, provider events | See inside a component that emits no events; enable kernel providers without an elevated session | Yes. The recorder's start/stop form is a command (`wpr -start CPU -filemode`, then `wpr -stop <out>.etl`, `observed`), and the parser is another (`tracerpt <in>.etl -o <out>.xml -of XML -summary <counts>.txt`, `observed`). The host probe reports this category as available when either the recorder or the session manager is present, with the elevation caveat in the same row |
| Language runtimes | Read a binary whose compiler emitted a runtime, a metadata blob and a symbol scheme of its own | Read a different language's binary; the mismatched tools produce plausible wrong output rather than an error | Yes |

## The scriptable-versus-GUI split, and what to do about it

The split is not a preference, it is a property of how the tool exposes itself. A tool is scriptable
when it has a documented non-interactive entry point whose output a program can parse: a command with
arguments, a script interpreter, or an SDK. It is GUI-only when the only interface is a window whose
controls are meant for a human.

**The rule for a GUI-only tool: ask for it.** When the capability the task needs is owned by a GUI-only
tool, the correct action is to request that a human run it and report the result — not to replace it
with a weaker method that can be scripted, because the weaker method's output then gets treated as if
it answered the same question. The concrete failure this prevents: reaching for string extraction or a
raw instruction listing because a decompiler is interactive, then treating a plausible-looking listing
as if it were a recovered structure.

The rule in the other direction is just as important: a GUI-only tool is not a substitute for the
command-line engine. When the question is "what does this function do at this moment with these
arguments", the engine answers it unattended; the GUI is for the case where a human is reading.

## Version and bitness alignment

Tools that come in pairs fail when the halves do not match, and the failure usually does not name the
mismatch. What to align, with the evidence for each:

- **A debugger and the library it uses to read images and symbols.** A version mismatch between them
  is treated as a fatal error by default, and continuing past it is a deliberate option (`observed`,
  the engine's option reference documents an ignore-this-error switch whose entire reason to exist is
  version mismatch). If a session dies immediately on start, check versions before reading anything
  into the target's behaviour.
- **Debugger bitness and target bitness.** A tool built for one width cannot drive a target of the
  other, and the platform exposes separate entry points for the 32-bit-on-64-bit case (`observed`, the
  thread-context documentation names the 32-bit thread accessors for a 64-bit debugger).
- **Injected code and target bitness.** A 32-bit library cannot be injected into a 64-bit process and
  the reverse is equally true; the platform's own documentation states this for the callback-based
  injection route, and it carries over to any route that loads code in the target (`observed`).
- **A managed tool and the runtime version it targets.** The runtime's instrumentation interfaces are
  versioned, and a capability may exist only from a stated runtime version onward (`observed`, the
  recompilation interface's "available since" statement). Probe the installed runtimes rather than
  assuming one.
- **A scripting layer and the framework embedded in the target.** Bindings compiled against one version
  of an instrumentation framework will not drive another version's agent (`inferred`).
- **A runtime's tool and the runtime that produced the binary.** A binary produced by a Go compiler is
  read with that toolchain's symbol and disassembly tools (`go version`, `go tool nm [options] file...`,
  `go tool objdump [-S] [-gnu] [-s symregexp] binary [start end]`, all `observed` as usage on this
  host); a Rust binary needs a demangler for its symbol scheme; a managed assembly needs managed
  tooling. Reading a Go or Rust binary with a generic Windows disassembler produces a call structure
  that looks wrong because it is — the code is real, the framing is not.

## Interactive tools must not be driven blindly

An interactive tool has no stable machine interface. Driving one by sending keystrokes or menu
navigations produces a session whose behaviour depends on focus, timing and whatever dialog happened
to appear, and the typical failure mode is not an error but an indefinite wait that looks like "still
working". Three rules:

1. Use the command-line engine that shares the interactive tool's engine when one exists; that is what
   it is for, and it accepts a full command list up front.
2. If a tool offers a script file rather than a command string, that file is the interface: write it,
   pass it, and bound the run with a timeout derived from one measured run rather than an assumed one.
3. Never drive a GUI tool from a script. Ask for it, or use the scriptable tool that owns the same
   question, and if no such tool exists, report the capability as unavailable-for-unattended-use rather
   than reporting the answer from a substitute.

## Budget rules that apply to every tool in this file

The most common way a long session is lost is not a wrong conclusion. It is a tool returning more than
a reader can consume, followed by a re-run to "get a smaller answer".

- **A bounded summary over a complete retained record.** Every producer that can emit a large result
  prints a bounded summary and writes the complete record to a path it reports. Read the summary;
  open the file only for the specific question the summary left open. For a tool you did not write, the
  same discipline applies by redirection: keep the full output in a file, and read a bounded head,
  a count and an error summary from it.
- **Never re-run a producer to shrink its answer.** The second run costs the same as the first and
  returns no less. If the reported form is too long, that is a defect in the reporting step, not a
  reason to run the tool again.
- **Shrinking the collection is a different act from shrinking the report.** Reducing a trace's
  providers, raising a log level's threshold, narrowing a scan's address range or filtering to one
  process changes *what was captured*, and that is legitimate — it is a different experiment with a
  stated scope. Re-running the same capture to print less of it is not.
- **Bound every command, and derive the bound from a measurement.** Time the operation once, record
  it, and derive the deadline from that number. An unbounded call converts a stall into "still
  working", which is the one state from which no recovery is possible.

## When a tool really is absent

Name the capability, name the command that failed, and name the probe that says whether the machine has
it, then choose the route that the remaining tools support. A missing tool is a finding to report, and
reporting it costs one line, whereas silently substituting a weaker method costs the entire conclusion
that follows from it. The two probe invocations at the top of this file are the answer to "does this
machine have it", and they distinguish "not installed" from "installed where `PATH` does not reach" and
from "needs a restart, elevation or a specific CPU feature".

## Related material in this skill

For the instruments the debugging and instrumentation categories above feed into, and the failure modes
they share, load `references/dynamic-debugging.md` and `references/injection-and-hooking.md`. For what
the dump and repair category produces and what it leaves out, load `references/memory-and-dumps.md`.
