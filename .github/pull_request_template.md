<!--
Thanks for the change. Two conventions make review cheap here:

  1. Say what happened, and how strongly you know it. Every factual statement carries a grade:
     `observed` (a command exists and its output exists), `inferred` (reasoned from an observation,
     step not executed), or `unverified` (assumed, or reported elsewhere and never reproduced here).
  2. Name the files, not the intentions. "Update the docs" is not a change; a path and the line that
     goes in it is.

Read CONTRIBUTING.md before filling this in. Delete any section that genuinely does not apply, and
say why in the change summary. Do not delete the effect-surface checklist: completing it is the
point.
-->

## What this solves

<!-- The problem, in one paragraph, then the smallest reproduction. -->

Smallest reproduction (command, artifact, host):

```
<command as it was run>
```

Observed:

```
<the decisive lines of output>
```

Expected instead:

<!-- What should have happened, and why you believe that. Cite the file or the reference that
     states the expectation. -->

## What changed

<!-- One line per file, with what changed in it. -->

## Deliberately not included

<!-- The other problems you found and did not fix, and the scope you decided against. Include the
     things a reviewer would otherwise ask for. An empty list here means "I found nothing else",
     which is a claim. -->

## Effect surface

<!-- Tick everything this change can cause. Tick "documentation only" when nothing else applies.
     An unchecked box does NOT establish that nothing happened: it establishes that the checklist
     was not completed, and a reviewer will ask. -->

- [ ] Documentation only: prose, index rows, navigation, comments. No behaviour, no tooling.
- [ ] Reads files (a target, a fixture, a capture, a configuration).
- [ ] Executes a process, attaches to one, or otherwise drives another program.
- [ ] Injects instrumentation, hooks, or code into another process.
- [ ] Changes memory, registers, on-disk bytes, or a file's metadata.
- [ ] Contacts a network service, resolves a name, or sends a request.
- [ ] Works around a protection, a check, or a platform restriction.
- [ ] Adds or changes a gate, a test, or the CI wiring.
- [ ] Changes the always-loaded part of the skill (`SKILL.md`), its frontmatter, or its budget.

Notes on the boxes that need one:

<!-- A new script under scripts/ that only parses a file still ticks "reads files". A change that
     installs a hook ticks injection even when the hook is a no-op. If a box is not ticked because
     the capability exists but is not exercised by this change, say so here. -->

## Evidence

Strength of the evidence in this change:

- [ ] Executed: a command was run, and its output is quoted above or in the changed file.
- [ ] Derived: no command was run; the change follows from a mechanism or from another observation,
      and the file says so where the claim is made.
- [ ] Proposed: nothing was run and nothing is claimed to work; the change documents a route to test.

Commands that actually ran, with their results:

```
<command>
<result>
```

Artifacts and pins, where the change rests on them (digest of the original, digest of the output,
tool and version, host build):

<!-- A measurement without its pins cannot raise a grade, and a tool exiting zero is a statement
     about the tool, not about the target. Leave the pin fields empty only if nothing recorded here
     is measured. -->

Negative results (routes measured and failed, scenarios the target could not exercise):

<!-- These are the most valuable lines in the change. Record them instead of dropping them. -->

## Documents updated

<!-- Tick what applies and name the file. A new file that is not registered where its class requires
     it is unreachable. -->

- [ ] `skills/exe-reverse/references/routing.md` (a new reference or script, or a new symptom row)
- [ ] `skills/exe-reverse/SKILL.md` (entry-point text, gates, symptom index, budget)
- [ ] `skills/exe-reverse/references/coverage-and-limits.md` (a capability's grade or dependency)
- [ ] `skills/exe-reverse/references/evidence-summary.md` (a capability's evidence)
- [ ] `skills/exe-reverse/evidence/` (a machine-readable capability row)
- [ ] `skills/exe-reverse/references/pitfalls.md` (a failure worth a number)
- [ ] `skills/exe-reverse/references/precedents/` (a case, plus its register row)
- [ ] `docs/tool-verification/` (the measurement record for this pass)
- [ ] `README.md` (the repository-level description, and the root tool list if a tool changed)
- [ ] None of the above, because the change touches none of them

## Gates

Run from the repository root; paste the last line of each.

```
python check_repo.py
python check_refs.py
python check_routing.py
python check_budget.py
python check_commands.py
python -m pytest -q
```

Findings that existed before this change, and findings this change introduces:

<!-- Name both. "The gate was already red" is acceptable with the failing line quoted; silence about
     a new failure is not. -->

## Readiness declaration (a human owner completes this)

<!-- An agent must not fill this in, and a reviewer must not accept it from an agent. It is the
     statement that a person has read the change and accepts the claim. Delete the instruction
     lines, keep the checkboxes. -->

- [ ] I have read the diff, and the claims in it are graded the way I would grade them myself.
- [ ] The effect surface above is complete, including what the change can do to a machine it runs on.
- [ ] The evidence grade is the strongest the change actually supports, and no chain is graded above
      its weakest link.
- [ ] Nothing here should have been excluded for identity, licence or privacy reasons.

Signed (name, and the role in which you accept it):
