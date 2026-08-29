# Decision Surface POC

Spike: visualize a Rego policy's decision surface as a 2D grid.

## Running

Two processes. Terminal 1:

    opa run --server --addr localhost:8181

Terminal 2:

    npm run dev

Vite proxies `/opa/*` to the OPA server (see `vite.config.ts`).

## Why a server and not wasm

Regorus has no published npm package — `regorusjs` was published and
unpublished on 2024-01-28, and nothing since. The wasm binding exists in
the repo but is build-from-source only. Falling back to the real `opa`
binary in server mode: policies are uploaded via `PUT /v1/policies/<id>`
and evaluated via `POST /v1/data/<path>`.

## Phase 0 proof

    node scripts/phase0.mjs

## Three views over one sweep

Every discovered field is swept (full cross product, capped at 400
combinations), and all three views read from that single sweep.

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

## Known soft spot

The decision graph is induced from sampled evaluations, not from OPA's
semantics. Within the swept value sets it is exact, but it says nothing about
values that were never swept. `/v1/compile` (partial evaluation) would give the
real residual structure and is the honest upgrade path.
