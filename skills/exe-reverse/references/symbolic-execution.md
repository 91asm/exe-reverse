# Symbolic Execution and Emulation

Goal: know when a solver or an emulator is cheaper than reading, how to frame the question so it has an
answer, and how to tell a validated result from a plausible one.

## When to load this

Load it when reading has stopped producing progress and the reason is the code's shape:

- an opaque predicate you need to be certain about, not merely confident about
- a byte-level algorithm you must recover exactly, because the deliverable is a generator rather than a
  patched binary
- a licence check where you need **an input that makes it pass**, not an understanding of the check
- a branch that is impractical to reach by hand, because reaching it needs state you cannot construct
- a virtualised region whose semantics you need, but whose instructions you cannot read

It is a route with a real cost, so name its failure modes before starting: a symbolic run that finishes is
not a symbolic run that is right.

## The question decides the route

The most expensive mistake in this area is framing the question too broadly. "What does this program do"
has no cheap answer and is almost never what the task needs. The four useful question shapes:

| Question | Route | Cost |
|---|---|---|
| What is the output for this input? | Run it, or emulate it concretely. No solver needed | Minutes |
| Does this branch have any input that takes it? | Symbolic exploration with the branch as the target, or a solver query on the path constraint | Bounded by the branch's dependency set |
| Which arm of an opaque predicate is taken? | One run, traced. The target answers this itself | One run |
| What input satisfies this condition? | Symbolic execution to a target condition, then validation | Bounded by the symbol set and the environment model |
| What is the algorithm? | Reconstruct it from observed input/output pairs, or lift a bounded range into an expression | Unbounded; scope it before starting |
| What does this program do? | Reclassify into one of the rows above | Not a question |

Two framings of the same work illustrate the difference. "What input makes this branch taken" is a
satisfiability question over the variables the branch depends on: the search space is the variables, the
answer is one witness, and the stop condition is a single satisfying assignment. "Recover the licence
algorithm" requires a complete description of a function over its whole input space, and no tool produces
that by itself. Ask the first question. The second is a conclusion you assemble from several first
questions.

A third framing saves entire sessions: ask for a **yes or no** before asking for a value. "Can this branch
be taken at all" terminates as soon as one path is found or every path is refuted, and it frequently
answers the real question without producing an input at all.

## The two shapes

**Concrete emulation with symbolic registers.** The code is executed by a CPU model, and the model's state
is either a concrete value or an expression over symbols. Branches are resolved by the concrete state
where it is known, and by a solver query where it is symbolic. There is no forking: each run follows one
path, which is the path the concrete state forces. This shape answers "what does this range compute" and
"what value does this expression have", and it is the shape that lifts a bounded range into an expression
you can read.

**Path-exploring symbolic execution.** The model forks at each branch, keeping a path constraint per path,
and the solver answers questions about those constraints: is this path satisfiable, and if so what
assignment satisfies it. This shape answers "what input reaches this point" and "what input makes this
comparison true". Cost grows with the number of branches and loops on the explored paths, and the growth is
the defining property of the method.

**Keeping a concrete seed.** A hybrid run starts from a real input, then symbolises selected values. The
seed keeps the path a path a real input takes, and it collapses the environment's behaviour to what was
actually observed. A purely symbolic run has no such anchor, and that is the origin of the failure
described below where the solver satisfies the condition through a path that cannot happen.

## What the tools need, and which part costs

Three models are required. Only one of them is usually the problem.

**The CPU model** supplies instruction semantics for the range you lift: registers, flags, stack effects,
and the exact width of every operation. An instruction the model does not implement correctly is a silent
source of a wrong answer, which is the main argument for keeping the lifted range small.

**The memory model** supplies an address space, and the distinction between concrete and symbolic regions.
Two questions decide how painful it is: whether a symbolic value is ever used as an address, and whether a
symbolic index can reach a symbolic region. The first forces a choice between concretising an address (which
picks one path and loses the others) and modelling memory as an array with an unconstrained index (which the
solver can handle but which enlarges the constraint set, `inferred`). Endianness and alignment are part of
this model, and getting them wrong produces an expression that is wrong in the low bytes only (`inferred`).

**The environment model** is the expensive one, and it is where these runs actually fail. Everything the
code calls is outside your model:

- Windows API calls are not self-contained. Their behaviour depends on handles, object state, the
  filesystem, the registry, the network, and time, so a stub that returns a chosen value is a *choice about
  the answer*, not a neutral act (`inferred`).
- Values that no model can compute must come from a real run. The clearest example is a clock:
  `QueryPerformanceCounter` is documented as a high-resolution timestamp whose counter frequency can be
  fixed at 10 MHz under a hypervisor rather than derived from hardware, and `GetTickCount64` is documented
  as having the resolution of the system timer, typically 10 to 16 milliseconds (`observed`). A model that
  emits a symbolic value for either of those lets the solver satisfy conditions that the real host would
  never produce (`inferred`).
- The process's own structures are environment too: the loader's data, the environment block, the module
  list. A check that reads one of them is reading a value you must supply.
- Concurrency is environmental. Code that runs on four threads in reality is executed on one path in the
  model, and any decision that depends on interleaving has no faithful model here.

**Stating the cost in the right place.** The solver is rarely the bottleneck, the environment is. A run
that needs eight stubbed calls has eight independent places where the model can disagree with the target,
and the count of stubs is a better predictor of a wrong answer than the size of the constraint set. Count
them and write the count down next to the result.

## Choosing the boundary

The boundary is the smallest code range that **contains the whole decision**.

1. **Start at the decision.** Find the comparison, the table lookup, or the branch that the deliverable
   turns on, and take the function that contains it.
2. **Symbolise the inputs.** The function's parameters, and the memory it reads that comes from outside,
   are symbols. Everything else stays concrete.
3. **Stub the side effects, and record every stub.** Each stub is a claim about the environment; a result
   without the stub list is not reproducible.
4. **Grow the boundary only while the branch depends on something outside it.** If the value compared comes
   from a caller, include the caller's computation, and stop when the dependency chain reaches a function
   parameter or a genuine input.
5. **Choose one boundary over many small experiments.** Five experiments on five small ranges carry five
   independent sets of stubs, and when their results disagree you cannot tell which stub was wrong. One
   larger range with one stub set can at least be validated as a unit.

**Three tests for a boundary that will work.** The range must have a definite entry point with a known
calling convention, so that the symbol set is well defined. The range must have a reachable end, so that a
completed run is a definite result rather than an unrolled approximation. And every variable the target
condition depends on must be either a symbol or computed inside the range; a dependency on outside state is
not a difficulty, it is a defect in the boundary.

**Where this is decided in practice.** If the check is one function and the value it compares arrives as a
parameter, the boundary is that function and the work is small. If the value is assembled by six called
helpers, hashing inputs read earlier in the run, the boundary is the assembler and the six helpers become
part of the model. This second case is where the environment cost appears, and the decision to make before
starting is whether the answer is cheaper to obtain by feeding the real target and observing than by
modelling.

## Why path explosion and an unconstrained environment produce a wrong answer

Both failure modes produce a *finishing* run with a confident answer, which is what makes them dangerous.

**Path explosion.** N independent branches produce 2^N paths, and an unbounded loop produces an unbounded
set (`inferred`). The symptoms are recognisable and worth treating as stop signals: the run does not finish;
memory grows without the path count reaching a plateau; the reported state count keeps climbing while
outputs are still being enumerated. The mitigations are all reductions of the question rather than
improvements of the engine: concretise every input that the target condition does not depend on, bound the
loops whose real trip counts are bounded, and ask for satisfiability instead of for all solutions.

**An unconstrained environment.** This is the failure that produces an answer that looks right. A stubbed
call returns an unconstrained value, the solver finds an assignment for it that satisfies the target
condition, and the resulting path is one the real target cannot take (`inferred`). The classic instance is a check that
is skipped on an error return: the solver sets the stub to the error value, the condition becomes
satisfiable, and the witness input is not a witness for anything. The answer is reproducible inside the
model and unreproducible in the world, and the model is the only thing that ever agreed with it.

**Two more sources of a confident wrong answer.** A concretised address that was not the address taken at
run time, which silently prunes the true path and explores a false one. And an instruction whose side
effect the model does not implement, typically a flag that is set by an arithmetic operation and read much
later, which shifts every downstream condition without any visible error. Both are `inferred` from how the models are built.

## Validation, which is not optional

A symbolic result is a hypothesis with excellent presentation. Three checks, all of them cheap next to the
cost of a wrong deliverable:

1. **Feed the witness to the real target.** The witness input must be accepted by the unmodified binary,
   under the same conditions as the control run, and must produce the target condition. This is the only
   check that validates the model, the boundary, and the environment claim at once.
2. **Re-check the recovered expression against the target.** If the deliverable is an expression or an
   algorithm, evaluate it over several inputs and compare against the target's own output for the same
   inputs. Agreement at the points the solver happened to touch proves nothing; agreement off those points
   is evidence.
3. **Reproduce the control first.** Before trusting any symbolic result, use the same boundary and the same
   stubs to reproduce the target's output for a known input. If the model cannot reproduce the control, the
   model is wrong and the target is not the thing to investigate.

**The stop rule.** When a witness fails validation, the boundary or the environment model was wrong, and the
next action is to re-open those two rather than to run the same question with a bigger solver budget. A
second run of the same model produces the same wrong answer with more confidence.

## When a solver is the wrong instrument

- **The value is readable.** A comparison against a constant string or a single byte is a reading task.
  Modelling the environment to solve it costs more than looking at it.
- **The state is almost entirely environmental.** When the decision depends on several API results, the
  model is a model of the environment, and the fast route is observation: trace the real run and read the
  values that were actually returned.
- **The answer is a patch.** If the deliverable is a binary whose behaviour changes at one site, the byte
  edit is the answer and the constraint becomes irrelevant.
- **One run answers it.** Which arm an opaque predicate takes is answered by executing it once, and no
  solver improves on that.
- **The structure, not the value, is the deliverable.** Lifting an expression does not produce a
  description of the algorithm. If the request is for an explanation, the trace-plus-reduction route in
  `virtualization-and-flattening.md` is the one that produces prose a reader can check.

## What this file does not contain

- No tool names, no command lines and no solver options. The methods above are what the tools implement,
  not what any one of them calls.
- No claim that any of this is automatic. Every boundary, every stub and every validation in this file is a
  decision made by the person running the work, and the failure modes exist because those decisions were
  left unmade.
- No sizes or limits. "Too many paths" and "too many stubs" are properties of a question and a host, and
  every number quoted for them elsewhere is someone else's question.
