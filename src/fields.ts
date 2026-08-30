// Deterministic field + value derivation from the OPA residual.
//
// extract.ts guesses fields by regex over source text. This derives them from
// the constraints OPA itself produced, so helper rules, variable bindings and
// bracket refs are all already resolved. Every value here exists because some
// branch actually tests it.

import { SENTINEL, type Field, type Value } from './extract'
import type { Constraint, Residual } from './compile'

export type DerivedField = Field & {
  /** Constraint kinds that produced this field, for the UI. */
  reasons: string[]
  /** True when some constraint on this path cannot be enumerated. */
  opaque: boolean
}

type Acc = {
  strings: Set<string>
  numbers: Set<number>
  booleans: boolean
  opaque: boolean
  reasons: Set<string>
}

function acc(): Acc {
  return { strings: new Set(), numbers: new Set(), booleans: false, opaque: false, reasons: new Set() }
}

function note(a: Acc, v: Value) {
  if (typeof v === 'string') a.strings.add(v)
  else if (typeof v === 'number') a.numbers.add(v)
  else if (typeof v === 'boolean') a.booleans = true
}

function absorb(a: Acc, c: Constraint) {
  switch (c.kind) {
    case 'compare':
      a.reasons.add(c.op)
      note(a, c.value)
      if (typeof c.value === 'number' && c.op !== '==' && c.op !== '!=') {
        // Boundary probe: the value itself plus both neighbours. planSweep is
        // required to keep all three (see analyze.ts).
        a.numbers.add(c.value - 1)
        a.numbers.add(c.value + 1)
      }
      break
    case 'member':
      a.reasons.add('in')
      for (const v of c.values) note(a, v)
      break
    case 'startswith':
      a.reasons.add('startswith')
      a.strings.add(c.prefix)
      a.strings.add(`${c.prefix}zz`)   // satisfies the prefix, differs from it
      break
    case 'truthy':
      a.reasons.add('truthy')
      a.booleans = true
      break
    case 'opaque':
      a.reasons.add(c.builtin)
      a.opaque = true
      break
  }
}

/**
 * Build the sweepable field set from a residual.
 *
 * A path carrying only opaque constraints (regex.match, net.cidr_contains)
 * gets no enumerable values - we surface it as opaque rather than inventing
 * values that would look authoritative and be wrong.
 */
export function fieldsFromResidual(residual: Residual): DerivedField[] {
  const byPath = new Map<string, Acc>()
  for (const b of residual.branches) {
    for (const c of b.constraints) {
      const targets = c.kind === 'opaque' ? c.paths : [c.path]
      for (const p of targets) {
        if (!p) continue
        const a = byPath.get(p) ?? acc()
        absorb(a, c)
        byPath.set(p, a)
      }
    }
  }

  const out: DerivedField[] = []
  for (const [path, a] of byPath) {
    const reasons = [...a.reasons].sort()
    // Pick the type with actual evidence. Strings win ties because a string
    // field swept as boolean loses every interesting value.
    if (a.strings.size > 0) {
      out.push({
        path, type: 'string',
        values: [...[...a.strings].sort(), SENTINEL],
        reasons, opaque: a.opaque,
      })
    } else if (a.numbers.size > 0) {
      out.push({
        path, type: 'number',
        values: [...a.numbers].sort((x, y) => x - y),
        reasons, opaque: a.opaque,
      })
    } else if (a.booleans) {
      // `undefined` = field absent, which Rego distinguishes from false.
      out.push({ path, type: 'boolean', values: [true, false, undefined], reasons, opaque: a.opaque })
    } else {
      // Opaque-only path: keep it visible, but with nothing to sweep.
      out.push({ path, type: 'string', values: [], reasons, opaque: true })
    }
  }
  return out.sort((x, y) => x.path.localeCompare(y.path))
}

/** Fields with at least one value, i.e. the ones a sweep can vary. */
export function sweepable(fields: DerivedField[]): Field[] {
  return fields.filter((f) => f.values.length > 0).map(({ path, values, type }) => ({ path, values, type }))
}

// ---------------------------------------------------------------- witnesses

/** Does `v` satisfy this constraint? Used to solve a path against ALL of its constraints. */
function satisfies(c: Constraint, v: Value): boolean {
  const yes = (b: boolean) => (c.kind !== 'compare' && c.negated ? !b : b)
  switch (c.kind) {
    case 'opaque':
      return false
    case 'compare': {
      // `negated` is already folded into `op` for equality by compile.ts.
      const eq = v === c.value
      switch (c.op) {
        case '==': return c.negated ? !eq : eq
        case '!=': return c.negated ? eq : !eq
        default: {
          if (typeof v !== 'number' || typeof c.value !== 'number') return false
          const r = c.op === '>' ? v > c.value
            : c.op === '>=' ? v >= c.value
            : c.op === '<' ? v < c.value
            : v <= c.value
          return c.negated ? !r : r
        }
      }
    }
    case 'member':
      return yes(c.values.some((x) => x === v))
    case 'startswith':
      return yes(typeof v === 'string' && v.startsWith(c.prefix))
    case 'truthy':
      // Rego: absent and false are both non-truthy; only true satisfies a
      // bare `input.x`, and absence is the cleanest way to satisfy `not`.
      return yes(v === true)
  }
}

/** Values worth trying for a path, derived from the constraints on it. */
function candidates(cs: Constraint[]): Value[] {
  const out: Value[] = []
  for (const c of cs) {
    if (c.kind === 'compare' && typeof c.value === 'number') {
      out.push(c.value - 1, c.value, c.value + 1)
    } else if (c.kind === 'compare') {
      out.push(c.value)
    } else if (c.kind === 'member') {
      out.push(...c.values)
    } else if (c.kind === 'startswith') {
      out.push(c.prefix, `${c.prefix}zz`)
    } else if (c.kind === 'truthy') {
      out.push(true, false)
    }
  }
  out.push(SENTINEL, undefined)
  const seen = new Set<string>()
  return out.filter((v) => {
    const k = JSON.stringify(v) ?? 'undefined'
    if (seen.has(k)) return false
    seen.add(k)
    return true
  })
}

/**
 * A concrete input that satisfies one branch.
 *
 * Stride sampling over the cross product aliases: with 131,220 combinations
 * and a 4,000 budget it deterministically skipped every value combination that
 * satisfied `write_method` and `api_path`, so four rules never fired and two
 * ALLOW routes looked unreachable. A witness is built FROM the branch, so each
 * route is exercised whatever the sampler happens to visit.
 *
 * Each path is solved against ALL of its constraints at once. Assigning them
 * one at a time let a later constraint clobber an earlier one - branch 5 sets
 * `input.path` from `startswith(_, "/api")` and again from
 * `not startswith(_, "/admin")`, and last-write-wins produced a witness that
 * satisfied neither.
 *
 * Returns null when a branch carries a constraint we cannot satisfy by
 * construction (an opaque builtin, or a genuinely conflicting pair) - we never
 * invent a value and claim it works.
 */
export function witnessFor(branch: { constraints: Constraint[] }): Record<string, Value> | null {
  const byPath = new Map<string, Constraint[]>()
  for (const c of branch.constraints) {
    if (c.kind === 'opaque') return null
    const list = byPath.get(c.path) ?? []
    list.push(c)
    byPath.set(c.path, list)
  }

  const out: Record<string, Value> = {}
  for (const [path, cs] of byPath) {
    const hit = candidates(cs).find((v) => cs.every((c) => satisfies(c, v)))
    if (hit === undefined && !cs.every((c) => satisfies(c, undefined))) return null
    out[path] = hit
  }
  return out
}

/** One witness per branch, skipping branches we cannot construct one for. */
export function witnesses(branches: { constraints: Constraint[] }[]): Record<string, Value>[] {
  const out: Record<string, Value>[] = []
  for (const b of branches) {
    const w = witnessFor(b)
    if (w) out.push(w)
  }
  return out
}
