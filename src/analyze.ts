// Sweeps the FULL cross product of every discovered field (not just two axes),
// then induces a decision tree from the results and builds Sankey flows.

import { SENTINEL, type Field, type Value } from './extract'
import type { RuleDef } from './instrument'

export type Row = {
  assignment: Record<string, Value>
  input: Record<string, unknown>
  decision: string          // "ALLOW" | "DENY" | a JSON value | "ERROR"
  fired: string[]           // ids of rules whose body was satisfied
}

export const MAX_COMBOS = 400

/** Trim per-field value lists until the cross product fits the budget. */
export function planSweep(fields: Field[]): { fields: Field[]; total: number; full: number } {
  const full = fields.reduce((n, f) => n * f.values.length, 1)
  const plan = fields.map((f) => ({ ...f, values: [...f.values] }))
  let total = full
  while (total > MAX_COMBOS) {
    // Shrink whichever field currently contributes the most breadth.
    const widest = plan.reduce((a, b) => (b.values.length > a.values.length ? b : a))
    if (widest.values.length <= 2) break
    widest.values.pop()
    total = plan.reduce((n, f) => n * f.values.length, 1)
  }
  return { fields: plan, total, full }
}

export function crossProduct(fields: Field[]): Record<string, Value>[] {
  let out: Record<string, Value>[] = [{}]
  for (const f of fields) {
    const next: Record<string, Value>[] = []
    for (const partial of out) {
      for (const v of f.values) next.push({ ...partial, [f.path]: v })
    }
    out = next
  }
  return out
}

/** input.a.b to { a: { b: v } }. undefined means "leave the field absent". */
export function assignmentToInput(assignment: Record<string, Value>): Record<string, unknown> {
  const input: Record<string, any> = {}
  for (const [path, value] of Object.entries(assignment)) {
    if (value === undefined) continue
    const parts = path.replace(/^input\./, '').split('.')
    let cur = input
    for (const p of parts.slice(0, -1)) {
      if (typeof cur[p] !== 'object' || cur[p] === null) cur[p] = {}
      cur = cur[p]
    }
    cur[parts[parts.length - 1]] = value
  }
  return input
}

/** Run `work` over items with bounded concurrency, preserving order. */
export async function mapLimit<T, R>(items: T[], limit: number, work: (t: T) => Promise<R>): Promise<R[]> {
  const out = new Array<R>(items.length)
  let next = 0
  await Promise.all(
    Array.from({ length: Math.min(limit, items.length) }, async () => {
      while (true) {
        const i = next++
        if (i >= items.length) return
        out[i] = await work(items[i])
      }
    }),
  )
  return out
}

// ---------------------------------------------------------------- decision tree

export type Tree =
  | { kind: 'leaf'; decision: string; count: number; rows: Row[] }
  | { kind: 'split'; path: string; count: number; children: { value: Value; node: Tree }[] }

export function induceTree(rows: Row[], paths: string[], valuesOf: Map<string, Value[]>): Tree {
  if (rows.length === 0) return { kind: 'leaf', decision: 'none', count: 0, rows: [] }

  const decisions = new Set(rows.map((r) => r.decision))
  if (decisions.size === 1 || paths.length === 0) {
    return { kind: 'leaf', decision: majority(rows), count: rows.length, rows }
  }

  // Split on whichever remaining field separates the outcomes best.
  let best: { path: string; gain: number } | null = null
  const base = entropy(rows)
  for (const path of paths) {
    const groups = groupBy(rows, path)
    let weighted = 0
    for (const g of groups.values()) weighted += (g.length / rows.length) * entropy(g)
    const gain = base - weighted
    if (!best || gain > best.gain) best = { path, gain }
  }
  if (!best || best.gain <= 1e-9) {
    return { kind: 'leaf', decision: majority(rows), count: rows.length, rows }
  }

  const rest = paths.filter((p) => p !== best!.path)
  const groups = groupBy(rows, best.path)
  const order = valuesOf.get(best.path) ?? []
  const children: { value: Value; node: Tree }[] = []
  for (const v of order) {
    const g = groups.get(keyOf(v))
    if (!g?.length) continue
    children.push({ value: v, node: induceTree(g, rest, valuesOf) })
  }

  // If every branch reaches the same decision, this field didn't matter here.
  const leafDecisions = children.map((c) => (c.node.kind === 'leaf' ? c.node.decision : null))
  if (leafDecisions.every((d) => d !== null && d === leafDecisions[0])) {
    return { kind: 'leaf', decision: leafDecisions[0]!, count: rows.length, rows }
  }
  return { kind: 'split', path: best.path, count: rows.length, children }
}

export function keyOf(v: Value): string {
  return v === undefined ? ' absent' : JSON.stringify(v)
}

function groupBy(rows: Row[], path: string): Map<string, Row[]> {
  const m = new Map<string, Row[]>()
  for (const r of rows) {
    const k = keyOf(r.assignment[path])
    const list = m.get(k) ?? []
    list.push(r)
    m.set(k, list)
  }
  return m
}

function entropy(rows: Row[]): number {
  const counts = new Map<string, number>()
  for (const r of rows) counts.set(r.decision, (counts.get(r.decision) ?? 0) + 1)
  let h = 0
  for (const c of counts.values()) {
    const p = c / rows.length
    h -= p * Math.log2(p)
  }
  return h
}

function majority(rows: Row[]): string {
  const counts = new Map<string, number>()
  for (const r of rows) counts.set(r.decision, (counts.get(r.decision) ?? 0) + 1)
  return [...counts.entries()].sort((a, b) => b[1] - a[1])[0][0]
}

// ---------------------------------------------------------------- path lint

export type PathSummary = {
  tests: { path: string; value: Value }[]
  decision: string
  count: number
  untested: string[]   // fields never tested along this route
  sentinels: string[]  // fields admitted at a value the policy never mentions
}

/** Enumerate root-to-leaf routes so we can ask "what did this route never check?" */
export function enumeratePaths(tree: Tree, allPaths: string[]): PathSummary[] {
  const out: PathSummary[] = []
  const walk = (node: Tree, tests: { path: string; value: Value }[]) => {
    if (node.kind === 'leaf') {
      const tested = new Set(tests.map((t) => t.path))
      out.push({
        tests,
        decision: node.decision,
        count: node.count,
        untested: allPaths.filter((p) => !tested.has(p)),
        sentinels: tests.filter((t) => t.value === SENTINEL).map((t) => t.path),
      })
      return
    }
    for (const c of node.children) walk(c.node, [...tests, { path: node.path, value: c.value }])
  }
  walk(tree, [])
  return out
}

// ---------------------------------------------------------------- sankey

export type Flow = { from: string; to: string; count: number }
export type SankeyData = {
  cols: string[][]        // node ids per column
  flows: Flow[]
  labels: Map<string, string>
}

/**
 * inputs -> rules -> decision. An input satisfying several rules gets its own
 * combined node ("R1+R3"), which keeps the flow conserved and makes redundant
 * rule overlap visible as a node in its own right.
 */
export function buildSankey(rows: Row[], sourcePath: string, rules: RuleDef[]): SankeyData {
  const labels = new Map<string, string>()
  const ruleLabel = new Map(rules.map((r, i) => [r.id, `R${i + 1}`]))

  const colA: string[] = []
  const colB: string[] = []
  const colC: string[] = []
  const flows = new Map<string, Flow>()

  const bump = (from: string, to: string) => {
    const k = `${from} ${to}`
    const f = flows.get(k) ?? { from, to, count: 0 }
    f.count++
    flows.set(k, f)
  }
  const reg = (col: string[], id: string, label: string) => {
    if (!labels.has(id)) { labels.set(id, label); col.push(id) }
  }

  for (const row of rows) {
    const v = row.assignment[sourcePath]
    const a = `in:${keyOf(v)}`
    reg(colA, a, v === undefined ? '<absent>' : String(v))

    const fired = row.fired.map((id) => ruleLabel.get(id) ?? id).sort()
    const b = `rule:${fired.join('+') || 'none'}`
    reg(colB, b, fired.length ? fired.join(' + ') : 'no rule (default)')

    const c = `out:${row.decision}`
    reg(colC, c, row.decision)

    bump(a, b)
    bump(b, c)
  }

  return { cols: [colA, colB, colC], flows: [...flows.values()], labels }
}
