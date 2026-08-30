# Decision Surface POC

Spike: visualize a Rego policy's decision surface, deriving the policy's
structure from OPA partial evaluation rather than from source-text guessing.

## Running

    npm start

That runs `scripts/dev.sh`, which starts the OPA server, waits for it to be
healthy, then starts Vite. Ctrl+C stops both. An OPA already listening on the
port is reused and left running on exit, so the script is safe to re-run.
Override the port with `OPA_PORT=8282 npm start`.

To run the two halves yourself instead:

    opa run --server --addr localhost:8181    # terminal 1
    npm run dev                               # terminal 2

Vite proxies `/opa/*` to the OPA server (see `vite.config.ts`).

## Why a server and not wasm

Regorus has no published npm package — `regorusjs` was published and
unpublished on 2024-01-28, and nothing since. The wasm binding exists in
the repo but is build-from-source only. Falling back to the real `opa`
binary in server mode: policies are uploaded via `PUT /v1/policies/<id>`
and evaluated via `POST /v1/data/<path>`.

## Phase 0 proof

    node scripts/phase0.mjs

## Where the structure comes from

The policy's structure is taken from OPA itself, not guessed from source text.
On every edit the app calls `/v1/compile` (partial evaluation) with `input`
marked unknown. OPA returns the RESIDUAL: the exact set of branches under
which the decision holds, with helper rules inlined and variable bindings
substituted. `compile.ts` parses that into typed constraints; `fields.ts`
derives the sweepable values from them.

This covers every Rego construct OPA supports, because it is OPA - bracket
refs, `some ... in`, comprehensions, arbitrary builtins. The regex scan in
`extract.ts` remains only as a fallback for when partial evaluation is
unavailable, and the banner at the top of the page says which one is in use.

A constraint we cannot enumerate (`regex.match`, `net.cidr_contains`) is kept
and flagged rather than dropped, so an unenumerable field is visible as such
instead of silently missing.

## Four views

**branches** - the residual's branches, which ARE the routes to the decision:
one entry per way the policy can say yes. Nothing is induced, so a route that
appears is reachable and a field absent from a route is genuinely
unconstrained on it. Each route carries a WITNESS - a concrete input built
from its own constraints, solved per path so no constraint clobbers another.

**graph** - a decision tree induced from the sweep results, splitting on
whichever field best separates the outcomes (information gain). Each root-to-leaf
route is one complete way to reach a decision. Two lints run over the routes:

  - routes that reach ALLOW while some field sits at the `<<other>>` sentinel,
    meaning a value the policy never mentions still gets in
  - routes that reach ALLOW without testing every field

**sankey** - inputs to rules to decision, with ribbon width the number of swept
inputs taking that route. Rule attribution is exact: `instrument.ts` appends a
synthetic copy of every rule body under a unique name, so one package
evaluation reports both the decision and which rules fired. An input satisfying
several rules gets its own combined node, so redundant overlap is visible.

**grid** - the original two-axis surface. Held fields can be pinned to a value
or left at `(any)`, which collapses that dimension and hatches cells whose
outcome depends on it.

## Examples

The **example** dropdown loads either fixture:

  - `authz` - 3 rules, 3 fields, 27 combinations. The small demo.
  - `gateway` - 17 rules, 10 fields, 5 branches, 131,220 combinations.
    Exercises value capping, sampling, witness seeding, and negation via a
    partial-evaluation support rule (`not admin_path`).

## What is exact and what is not

Exact, from OPA's own semantics:

  - the branch list in the **branches** view
  - the constraints on each branch, and which fields it leaves unconstrained
  - the field and value sets that feed the sweep
  - each branch witness (constructed from the branch, then confirmed by
    evaluating it)

Still sampled, and labelled as such in the status line:

  - **graph**, **sankey** and **grid**, which read from the sweep. When the
    cross product exceeds the budget the sweep is a sample, and the status line
    says so. It used to report a 0.8% sample as complete.

The sweep is seeded with one witness per branch before sampling begins.
Stride sampling aliases - on `gateway` it deterministically missed every
combination satisfying `write_method` and `api_path`, leaving four rules
unexercised and two ALLOW routes looking unreachable. Seeding removes that:
all 17 rules now fire.

Remaining gap: a branch constrained only by an opaque builtin gets no witness,
because we will not invent a value and present it as working. Satisfying those
needs per-builtin generators or a solver.
