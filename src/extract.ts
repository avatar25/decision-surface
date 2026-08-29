// Phase 2: find candidate input fields and the values worth sweeping, by
// scanning policy SOURCE TEXT. Deliberately not an AST — see README.

export type Value = string | number | boolean | undefined

export type Field = {
  path: string
  values: Value[]
  type: 'string' | 'number' | 'boolean'
}

export const SENTINEL = '«other»'
const MAX_VALUES = 12

const PATH = String.raw`input(?:\.[A-Za-z_]\w*)+`
const STR = String.raw`"(?:[^"\\]|\\.)*"`
const NUM = String.raw`-?\d+(?:\.\d+)?`
const BOOL = String.raw`true|false`
const LIT = `${STR}|${NUM}|${BOOL}`

type Evidence = { kind: Field['type']; value: string | number | boolean }

/** Parse one literal token into a typed evidence entry. */
function literal(tok: string): Evidence | null {
  const t = tok.trim()
  if (t.startsWith('"')) {
    try {
      return { kind: 'string', value: JSON.parse(t) as string }
    } catch {
      return null
    }
  }
  if (t === 'true') return { kind: 'boolean', value: true }
  if (t === 'false') return { kind: 'boolean', value: false }
  if (/^-?\d/.test(t)) return { kind: 'number', value: Number(t) }
  return null
}

/** Strip # comments so literals mentioned in prose don't become candidates. */
function stripComments(src: string): string {
  return src
    .split('\n')
    .map((line) => {
      let inStr = false
      for (let i = 0; i < line.length; i++) {
        const c = line[i]
        if (c === '\\' && inStr) { i++; continue }
        if (c === '"') inStr = !inStr
        else if (c === '#' && !inStr) return line.slice(0, i)
      }
      return line
    })
    .join('\n')
}

export function extractFields(source: string): Field[] {
  const src = stripComments(source)
  const found = new Map<string, Evidence[]>()

  const add = (path: string, ev: Evidence | null) => {
    if (!ev) return
    const list = found.get(path) ?? []
    list.push(ev)
    found.set(path, list)
  }

  // input.a.b == "x" / != 5 / == true
  for (const m of src.matchAll(new RegExp(`(${PATH})\\s*(?:==|!=)\\s*(${LIT})`, 'g'))) {
    add(m[1], literal(m[2]))
  }
  // "x" == input.a.b
  for (const m of src.matchAll(new RegExp(`(${LIT})\\s*(?:==|!=)\\s*(${PATH})`, 'g'))) {
    add(m[2], literal(m[1]))
  }
  // input.a.b in {"x", "y"} / ["x", "y"]
  for (const m of src.matchAll(new RegExp(`(${PATH})\\s+in\\s+(\\{[^}]*\\}|\\[[^\\]]*\\])`, 'g'))) {
    for (const lit of m[2].matchAll(new RegExp(LIT, 'g'))) add(m[1], literal(lit[0]))
  }
  // input.a.b > 5 (and >=, <, <=), both orientations. Boundary neighbours are
  // added later by the number value rule.
  for (const m of src.matchAll(new RegExp(`(${PATH})\\s*(?:>=|<=|>|<)\\s*(${NUM})`, 'g'))) {
    add(m[1], literal(m[2]))
  }
  for (const m of src.matchAll(new RegExp(`(${NUM})\\s*(?:>=|<=|>|<)\\s*(${PATH})`, 'g'))) {
    add(m[2], literal(m[1]))
  }
  // startswith(input.a.b, "x") -> "x" and a value that starts with it
  for (const m of src.matchAll(new RegExp(`startswith\\s*\\(\\s*(${PATH})\\s*,\\s*(${STR})\\s*\\)`, 'g'))) {
    const ev = literal(m[2])
    if (ev && ev.kind === 'string') {
      add(m[1], ev)
      add(m[1], { kind: 'string', value: `${ev.value}zz` })
    }
  }
  // Bare `input.a.b` or `not input.a.b` as a whole expression -> boolean field.
  for (const rawLine of src.split('\n')) {
    const line = rawLine.trim()
    const m = line.match(new RegExp(`^(?:not\\s+)?(${PATH})$`))
    if (m) add(m[1], { kind: 'boolean', value: true })
  }

  const fields: Field[] = []
  for (const [path, evidence] of found) {
    const type = dominantType(evidence)
    const values = buildValues(type, evidence)
    if (values.length === 0) continue
    fields.push({ path, values: values.slice(0, MAX_VALUES), type })
  }
  return fields.sort((a, b) => a.path.localeCompare(b.path))
}

/** A path can be compared against mixed literals; pick the best-supported type. */
function dominantType(evidence: Evidence[]): Field['type'] {
  const counts = { string: 0, number: 0, boolean: 0 }
  for (const e of evidence) counts[e.kind]++
  const order: Field['type'][] = ['string', 'number', 'boolean']
  return order.reduce((best, k) => (counts[k] > counts[best] ? k : best), order[0])
}

function buildValues(type: Field['type'], evidence: Evidence[]): Value[] {
  const mine = evidence.filter((e) => e.kind === type).map((e) => e.value)

  if (type === 'boolean') {
    // `undefined` = field absent entirely, which is distinct from false in Rego.
    return mine.length ? [true, false, undefined] : []
  }
  if (type === 'number') {
    const out: Value[] = []
    for (const n of mine as number[]) out.push(n - 1, n, n + 1)
    return dedupe(out)
  }
  const out = dedupe(mine as string[])
  // The sentinel is what reveals the default / else region.
  return out.length ? [...out, SENTINEL] : []
}

function dedupe(values: Value[]): Value[] {
  const seen = new Set<string>()
  const out: Value[] = []
  for (const v of values) {
    const key = JSON.stringify(v) ?? 'undefined'
    if (seen.has(key)) continue
    seen.add(key)
    out.push(v)
  }
  return out
}
