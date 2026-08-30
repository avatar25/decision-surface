// Deterministic policy structure via OPA partial evaluation (`/v1/compile`).
//
// This replaces the regex scan in extract.ts as the primary source of truth.
// We hand OPA the policy with `input` marked unknown; it hands back the
// RESIDUAL: the exact set of branches under which the decision holds, with
// every helper rule inlined and every variable binding substituted.
//
// Because the residual comes from OPA's own evaluator, it covers every Rego
// construct OPA supports - bracket refs, comprehensions, `some ... in`,
// arbitrary builtins - none of which the regex could see.

import type { Value } from './extract'

export type CompareOp = '==' | '!=' | '>' | '>=' | '<' | '<='

export type Constraint =
  | { kind: 'compare'; path: string; op: CompareOp; value: Value; negated: boolean; text: string }
  | { kind: 'member'; path: string; values: Value[]; negated: boolean; text: string }
  | { kind: 'startswith'; path: string; prefix: string; negated: boolean; text: string }
  | { kind: 'truthy'; path: string; negated: boolean; text: string }
  | { kind: 'opaque'; builtin: string; paths: string[]; negated: boolean; text: string }

/** One complete way to reach the decision. Constraints are ANDed. */
export type Branch = { constraints: Constraint[] }

export type Residual = {
  branches: Branch[]
  paths: string[]        // every input path the residual mentions
  opaquePaths: string[]  // paths only reachable through a builtin we cannot enumerate
  alwaysTrue: boolean    // residual is unconditionally true
  alwaysFalse: boolean   // decision is unreachable
}

// ------------------------------------------------------------------ AST terms

type Term = { type: string; value: any }

/** `input.user.role` from a ref term, or null when the ref is not rooted at input. */
function refPath(t: Term | undefined): string | null {
  if (!t || t.type !== 'ref' || !Array.isArray(t.value) || t.value.length === 0) return null
  const [head, ...rest] = t.value as Term[]
  if (head.type !== 'var' || head.value !== 'input') return null
  const parts: string[] = ['input']
  for (const p of rest) {
    // A var here is an iteration variable (input.roles[i]); mark it so the
    // path stays honest rather than pretending to be a concrete field.
    if (p.type === 'string') parts.push(String(p.value))
    else if (p.type === 'var') parts.push('[_]')
    else if (p.type === 'number') parts.push(`[${p.value}]`)
    else return parts.join('.')
  }
  return parts.join('.')
}

/** Dotted name of a builtin ref, e.g. "internal.member_2", "regex.match". */
function refName(t: Term | undefined): string | null {
  if (!t || t.type !== 'ref' || !Array.isArray(t.value)) return null
  return (t.value as Term[]).map((x) => String(x.value)).join('.')
}

function scalar(t: Term | undefined): { ok: true; value: Value } | { ok: false } {
  if (!t) return { ok: false }
  if (t.type === 'string') return { ok: true, value: String(t.value) }
  if (t.type === 'number') return { ok: true, value: Number(t.value) }
  if (t.type === 'boolean') return { ok: true, value: Boolean(t.value) }
  if (t.type === 'null') return { ok: true, value: undefined }
  return { ok: false }
}

function collection(t: Term | undefined): Value[] | null {
  if (!t || (t.type !== 'set' && t.type !== 'array') || !Array.isArray(t.value)) return null
  const out: Value[] = []
  for (const item of t.value as Term[]) {
    const s = scalar(item)
    if (!s.ok) return null
    out.push(s.value)
  }
  return out
}

/** Readable source-like rendering of a term, for the UI and for opaque text. */
function render(t: Term | undefined): string {
  if (!t) return '?'
  switch (t.type) {
    case 'string': return JSON.stringify(t.value)
    case 'number': case 'boolean': return String(t.value)
    case 'null': return 'null'
    case 'var': return String(t.value)
    case 'ref': return refPath(t) ?? refName(t) ?? 'ref'
    case 'set': return `{${(t.value as Term[]).map(render).join(', ')}}`
    case 'array': return `[${(t.value as Term[]).map(render).join(', ')}]`
    case 'call': return `${render((t.value as Term[])[0])}(...)`
    default: return t.type
  }
}

/** Every input path mentioned anywhere inside a term tree. */
function pathsIn(t: Term | undefined, out: Set<string> = new Set()): Set<string> {
  if (!t) return out
  const p = refPath(t)
  if (p) out.add(p)
  if (Array.isArray(t.value)) for (const c of t.value as Term[]) if (c && typeof c === 'object' && 'type' in c) pathsIn(c, out)
  return out
}

const FLIP: Record<string, CompareOp> = { gt: '<', gte: '<=', lt: '>', lte: '>=' }
const DIRECT: Record<string, CompareOp> = { gt: '>', gte: '>=', lt: '<', lte: '<=' }

// ------------------------------------------------------------------ expressions

/**
 * Turn one residual expression into a constraint. Support rules referenced by
 * the expression are inlined via `support`, so `not admin_path` becomes a real
 * negated startswith rather than an opaque data reference.
 */
function toConstraints(expr: any, support: Map<string, any[]>): Constraint[] {
  const negated = Boolean(expr.negated)
  const terms = expr.terms
  // `not` belongs in every rendering, not just the bare-ref one. Omitting it
  // showed `not admin_path` as plain `startswith(...)` - the exact opposite.
  const neg = (t: string, n = negated) => (n ? `not ${t}` : t)

  // Bare ref: either a truthiness test on input, or a support-rule reference.
  if (!Array.isArray(terms)) {
    const p = refPath(terms)
    if (p) return [{ kind: 'truthy', path: p, negated, text: neg(p) }]
    const name = refName(terms)
    const body = name ? support.get(name) : undefined
    if (body) {
      // Inline the support rule, flipping negation onto each inner constraint.
      // Sound only for a single-expression body; a conjunction under `not` is
      // a disjunction, which we cannot express as a flat AND - keep it opaque.
      const inner = body.flatMap((e) => toConstraints(e, support))
      if (!negated || inner.length === 1) {
        // Flipping the flag must re-render the text too, or the UI shows the
        // inner rule's polarity instead of the inlined one.
        return inner.map((c) => {
          const flipped = negated !== c.negated
          if (flipped === c.negated) return c
          const text = flipped
            ? `not ${c.text}`
            : c.text.replace(/^not /, '')
          return { ...c, negated: flipped, text }
        })
      }
      return [{
        kind: 'opaque', builtin: name!, negated,
        paths: [...new Set(inner.flatMap((c) => (c.kind === 'opaque' ? c.paths : [c.path])))],
        text: `not (${inner.map((c) => c.text).join(' AND ')})`,
      }]
    }
    return [{ kind: 'opaque', builtin: name ?? 'expr', paths: [], negated, text: render(terms) }]
  }

  const [op, a, b] = terms as Term[]
  const name = refName(op) ?? ''

  if (name === 'eq' || name === 'equal' || name === 'neq') {
    const wantNeq = name === 'neq'
    const pa = refPath(a), pb = refPath(b)
    const sa = scalar(a), sb = scalar(b)
    const baseOp: CompareOp = wantNeq !== negated ? '!=' : '=='
    if (pa && sb.ok) return [{ kind: 'compare', path: pa, op: baseOp, value: sb.value, negated: false, text: `${pa} ${baseOp} ${render(b)}` }]
    if (pb && sa.ok) return [{ kind: 'compare', path: pb, op: baseOp, value: sa.value, negated: false, text: `${pb} ${baseOp} ${render(a)}` }]
    // baseOp already folded `negated` in above, so the text must not repeat it.
    // Non-scalar or path-to-path equality: real, but not enumerable.
    const paths = [...pathsIn(a), ...pathsIn(b)]
    return [{ kind: 'opaque', builtin: name, paths, negated: false, text: `${render(a)} ${baseOp} ${render(b)}` }]
  }

  if (name in DIRECT) {
    const pa = refPath(a), pb = refPath(b)
    const sa = scalar(a), sb = scalar(b)
    if (pa && sb.ok) return [{ kind: 'compare', path: pa, op: DIRECT[name], value: sb.value, negated, text: neg(`${pa} ${DIRECT[name]} ${render(b)}`) }]
    if (pb && sa.ok) return [{ kind: 'compare', path: pb, op: FLIP[name], value: sa.value, negated, text: neg(`${pb} ${FLIP[name]} ${render(a)}`) }]
  }

  if (name === 'internal.member_2') {
    const p = refPath(a)
    const vals = collection(b)
    if (p && vals) return [{ kind: 'member', path: p, values: vals, negated, text: neg(`${p} in ${render(b)}`) }]
  }

  if (name === 'startswith') {
    const p = refPath(a)
    const s = scalar(b)
    if (p && s.ok && typeof s.value === 'string') {
      return [{ kind: 'startswith', path: p, prefix: s.value, negated, text: neg(`startswith(${p}, ${render(b)})`) }]
    }
  }

  // Anything else is a real constraint we cannot enumerate: regex.match,
  // net.cidr_contains, count, time.*. Keep it, flag it, never silently drop it.
  const paths = [...new Set((terms as Term[]).slice(1).flatMap((t) => [...pathsIn(t)]))]
  return [{
    kind: 'opaque', builtin: name || 'call', paths, negated,
    text: neg(`${name}(${(terms as Term[]).slice(1).map(render).join(', ')})`),
  }]
}

// ------------------------------------------------------------------ entry point

export type CompileOutcome =
  | { ok: true; residual: Residual }
  | { ok: false; error: string }

/**
 * Ask OPA for the residual of `entrypoint` with `input` unknown.
 * `data` stays known so external data is resolved rather than left symbolic.
 */
export async function compileResidual(entrypoint: string): Promise<CompileOutcome> {
  const query = `${entrypoint.trim()} == true`
  let body: any
  try {
    const res = await fetch('/opa/v1/compile', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query, unknowns: ['input'] }),
    })
    body = await res.json()
    if (!res.ok) {
      const errs = Array.isArray(body?.errors)
        ? body.errors.map((e: any) => `${e.code ?? 'error'}: ${e.message}`).join('\n')
        : body?.message
      return { ok: false, error: errs ?? `compile failed (${res.status})` }
    }
  } catch (e) {
    return { ok: false, error: `cannot reach opa /v1/compile (${String(e)})` }
  }
  return { ok: true, residual: parseResidual(body.result ?? {}) }
}

/** Exported for tests: turn a raw /v1/compile result into branches. */
export function parseResidual(result: any): Residual {
  const support = new Map<string, any[]>()
  for (const mod of result.support ?? []) {
    const pkg = (mod.package?.path ?? []).map((p: any) => String(p.value)).join('.')
    for (const rule of mod.rules ?? []) {
      const nm = rule.head?.name ?? (rule.head?.ref ?? []).map((r: any) => String(r.value)).join('.')
      if (nm) support.set(`${pkg}.${nm}`, rule.body ?? [])
    }
  }

  const queries: any[][] = result.queries ?? []
  // No queries at all = the decision can never hold. A single empty query =
  // it holds unconditionally.
  const alwaysFalse = queries.length === 0
  const alwaysTrue = queries.some((q) => q.length === 0)

  const branches: Branch[] = queries
    .filter((q) => q.length > 0)
    .map((q) => ({ constraints: q.flatMap((e) => toConstraints(e, support)) }))

  const paths = new Set<string>()
  const opaqueOnly = new Set<string>()
  for (const b of branches) {
    for (const c of b.constraints) {
      if (c.kind === 'opaque') { for (const p of c.paths) { paths.add(p); opaqueOnly.add(p) } }
      else { paths.add(c.path); opaqueOnly.delete(c.path) }
    }
  }

  return {
    branches,
    paths: [...paths].sort(),
    opaquePaths: [...opaqueOnly].sort(),
    alwaysTrue,
    alwaysFalse,
  }
}
