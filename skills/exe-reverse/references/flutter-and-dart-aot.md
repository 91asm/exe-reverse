# Flutter and Dart AOT snapshots

Goal: recognise a Flutter application from its file layout, find the layer that actually holds the
behaviour, and know exactly how far a static pass can get before it needs version-matched tooling.

## When to load this

Load this when a target ships `flutter_windows.dll`, when a directory contains a large
`data/app.so` beside a small launcher executable, when `strings` on a Windows binary starts
returning Dart class names, or when an installer has been extracted and the payload contains a
`flutter_assets` tree. The symptom index routes "the target is a .NET assembly and hex-patching it
does nothing" and "strings you expect are absent" here when the artifact turns out to be neither
native C++ nor managed.

A Flutter desktop application is the one common shape where the ordinary Windows workflow inverts:
there is no meaningful native code to patch, no import table worth reading, and no symbol table,
and the behaviour you were asked to change is in a compiled Dart snapshot.

## The shape, measured

Everything in this section was measured on one shipping application: a 31,059,248-byte Inno Setup
installer, extracted with `innoextract`, whose payload contained a 26,821,600-byte
`app/data/app.so`. `observed`.

| Property | Value | What it means |
|---|---|---|
| Container of the download | Inno Setup 6.1.0, unicode | The download is an installer, not the program. Extract before analysing (`installers-and-packaging.md`) |
| The launcher beside the engine | 73.6 KiB | A launcher. It starts the engine and does nothing interesting |
| `data/app.so` | 26.8 MB, **ELF64, x86-64, ET_DYN** | The compiled Dart. An **ELF** shared object inside a Windows application |
| `.text` | 16.7 MB, flags `0x6` (alloc + execute) | The AOT-compiled Dart code |
| `.rodata` | 10.1 MB | Read-only data: string literals, constants, metadata |
| `.dynsym` | 144 bytes | Six symbols. The image is stripped of everything useful |
| `.eh_frame` | 66 bytes | No unwinding data, so a stack walk gives you nothing |
| relocation sections | **none** | No `.rela.dyn` or `.rela.plt` at all |
| `.rodata` strings | reconstructed by offset | Literals survive AOT compilation and are readable |

Two consequences follow immediately, and both are the opposite of a native target:

**You cannot patch the code without understanding the snapshot format.** The Dart compiler emits
its own object layout, and an edit that changes a byte in `.text` is an edit to compiled Dart with
no symbols, no types and no function boundaries you can trust.

**The launcher is not the program.** Patching the small launcher executable achieves nothing; it is
an engine bootstrap. This is the desktop analogue of the mistake of patching a dex loader instead
of the loaded code.

## How references work, and why the obvious method fails

The natural first move for a stripped binary is: find a string, then find the instruction that
loads its address. On this image that method returns a confidently wrong answer, and the
measurement is worth recording because a plausible-looking negative is worse than no answer.
**A byte scan over `.text` reports instruction shapes that are not there, and the way it fails is
worth recording in full**, because every step of it looked like evidence.

Three models were tried against this image, and two were disposed of by measurement before the third
was believed:

| Model | What was measured | Verdict |
|---|---|---|
| a self-relative load, `mov r64, [rip+disp32]`, whose displacement names the literal | a few hundred byte-pattern hits, **none** landing in the read-only data | refuted, wrongly read as "this image does not reference its data that way" |
| a table of absolute addresses in the data section | **no** run of 8-byte words pointing into the image, across all 10 MB | refuted |
| a compressed-pointer pool: 4-byte tagged values inside the data section | a contiguous run of 97,751 such values, 100% in range against a 0.23% random baseline, slots that appeared to name literals once a tag bit was cleared | **believed, and wrong** |

The third model produced the kind of result that is easiest to accept, and a real disassembler
disposes of it in two lines (`observed`; capstone, installed on this host):

| Measurement | Result |
|---|---|
| `mov r15, imm64` found by byte pattern, immediates examined | nine, whose "immediates" are plainly other instructions (`0xF8458B48C1894800` decodes as `mov rcx, rax; mov rax, [rbp-8]`) -- the pattern matched *inside* operands |
| genuine writes to `r15`, decoded at real instruction boundaries | **zero** |
| `[r15 + disp]` operands, decoded at real instruction boundaries | **zero** |

The cause is structural rather than a coding slip. A byte pattern over variable-length code has no
notion of where instructions begin, so it matches inside operands and inside data. `.text` here also
opens with zero padding and the ELF entry point is **0**, because this artifact is a shared object
rather than a program, so there is no address from which a reliable sweep can start. The earlier
counts were measuring the scanner, not the image.

**What survives, and what is withdrawn.** Literal recovery is unaffected: it scans printable runs,
which needs no instruction boundaries and can be checked by eye. Every claim about *which code*
references a literal is withdrawn, and the tool no longer reports one.

**What would be needed.** Reference sites require the snapshot's own layout parsed, which means
tooling built for the exact release that produced the file. `observed`: the release here is **3.3.4**,
read from the companion executable's runtime string rather than from the stripped payload, which
carries no version at all. State the boundary instead of working around it -- "the literals name the
feature and its vocabulary; the code that reads them is not reachable with what is installed here" is
a true, useful report, and it is the one this file supports.

## Locating behaviour: what works, and in what order

1. **Extract the installer first.** Everything below operates on the payload, and the payload is
   what `app.so` is inside.
2. **Confirm the shape.** `scripts/dart_snapshot_strings.py app.so` prints the section layout, and
   the layout is the identification: a very large code section, a large data section, a symbol table
   measured in bytes, and an unwinding table that is a stub. Nothing needs disassembling to see it,
   which matters because the disassembly is the part that cannot be trusted here.
3. **Recover literals and search them.** `scripts/dart_snapshot_strings.py app.so --find premium,licen,vip`
   is the cheapest step that produces real leads, because a string literal survives AOT compilation
   and minification while names do not. Both one-byte (UTF-8) and two-byte (UTF-16) literals are
   recovered, because a localised application carries both.
4. **Read the literals as a map, not as a verdict.** On the measured target a single `--find`
   returned feature-gate messages that name the product's own tier system, an enum type
   (`AccountPremiumRequirementType`), a result type (`PremiumLicenseUpgradeResult`), a route name
   (`page_premium_upgrade`), a storage flag (`license_migration_notification_shown`) and a
   method name (`parseLicenses`). That is enough to write a plan and not enough to make a claim:
   the literals tell you the feature exists and what the product calls it.
5. **Then parse the pool** if you need the sites that use a literal. This needs the snapshot
   structure decoded, which means tooling built for the exact Dart release. Two public options
   exist and both are external: one is a standalone binary that reads a snapshot directly, the
   other is built from source and needs the Dart version to match. Neither is shipped here.
6. **Watch the version boundary.** A snapshot is produced by one Dart release and the tooling must
   match it. `flutter --version` from the payload, or the engine's own version string, is the
   input; a mismatched parser fails in ways that look like a corrupted file.

## What cannot be done from the file alone

- **No symbol recovery.** There is nothing to recover: the image is stripped by design, not by an
  accident of the build.
- **No honest function boundaries without the pool.** The Dart compiler lays out code by its own
  rules; a disassembler's guess at a function start is a guess.
- **No patch-and-run without repairing the snapshot's own integrity expectations.** A modified
  `app.so` that the engine refuses produces a startup failure, not a diagnostic. Establish the
  build's own checks before assuming a byte edit is enough.
- **No conclusion about a server-side tier.** A Flutter client renders what it is told; the
  literals above describe client-side gates, and which of them are decided locally is exactly the
  classification question in `license-mechanisms.md`.
- **Patching the launcher, the plugin DLLs or the assets.** None of them holds the behaviour. If a
  plan names one of those, the layer diagnosis is wrong.

## The handoff to the rest of this skill

Once the snapshot is understood, the ordinary questions apply again, and they are answered
elsewhere: which decision is client-side (`license-mechanisms.md`), how to observe it without a
symbol (`hardware-tracing.md`), whether the change can be proven (`verification.md`), and what a
deliverable may even be when the code is compiled Dart (`handoff-boundaries.md`).

**State the boundary out loud when reporting.** "The literals show the client names this tier, and
the decision site is inside a compiled snapshot that this repository cannot parse" is a true and
useful sentence. "The premium check is at that string" is not supported by anything in this file.
