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
| `.rodata` | 10.1 MB | Object pool, string literals, metadata |
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
`observed`, over the whole 16.7 MB `.text`:

| Idiom | Occurrences |
|---|---|
| `mov r64, [r15 + disp32]` — a load through a register-held base | **110,641** |
| `mov r64, [rip + disp32]` — a self-relative load | **554** |
| …of those, targets landing anywhere in `.rodata` | **0** |

Dart's AOT code reaches its data through an **object pool**, held in a callee-saved register
(`r15` on this target, which is a compiler choice rather than a rule), and the pool lives in the
read-only data. Self-relative loads exist but never address the literal region.

So an instruction scan for "who references this string" finds nothing, and reporting "0
references" from it is a false negative dressed as a result. The 8-byte values in `.rodata` that
look like pointers into the literal region are the literal *data itself* being misread: their
targets land at offsets like `+3` inside other strings.

**The correct route is to parse the object pool**, not to scan instructions. That is what
version-matched snapshot tooling does.

## Locating behaviour: what works, and in what order

1. **Extract the installer first.** Everything below operates on the payload, and the payload is
   what `app.so` is inside.
2. **Confirm the shape.** `scripts/dart_snapshot_strings.py app.so --observe` prints the section
   layout and the two instruction counts above. A large pool-load count with near-zero
   self-relative loads identifies this family of image immediately, and tells you not to spend a
   session on instruction scanning.
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
