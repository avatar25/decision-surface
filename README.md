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

Note: the OPA server keeps uploaded policies until deleted. Everything here
uses the single policy id `spike`, so repeated uploads replace rather than
stack. If you ever upload under another id you'll get
`multiple default rules ... found`.
