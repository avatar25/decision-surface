// Rewrites a policy so we can tell WHICH rule produced a decision.
//
// OPA's REST trace doesn't carry source locations, so instead of parsing a
// trace we append a synthetic copy of every rule body under a unique name:
//
//     allow if { input.role == "admin" }   ->   __ds_0 if { input.role == "admin" }
//
// Evaluating the whole package then returns { allow: true, __ds_0: true },
// which is exact rule attribution in a single request. Rules that did not
// fire are simply absent from the result.

export type RuleDef = {
  id: string      // "__ds_0"
  name: string    // the head this rule defines, e.g. "allow"
  line: number    // 1-based line of the rule head, for source linking
  body: string    // body text, shown in the UI
}

const HEAD_BLOCK = /^([a-z_]\w*)\s*(?::=\s*[^{]+?)?\s+if\s*\{\s*$/
const HEAD_BLOCK_V0 = /^([a-z_]\w*)\s*(?::=\s*[^{]+?)?\s*\{\s*$/
const HEAD_INLINE = /^([a-z_]\w*)\s*(?::=\s*[^{]+?)?\s+if\s+(.+?)\s*$/

export function instrument(policy: string): { source: string; rules: RuleDef[] } {
  const lines = policy.split('\n')
  const rules: RuleDef[] = []
  const synthetic: string[] = []

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]
    const trimmed = line.trim()
    // `default` has no body to attribute; `else` bodies belong to their parent.
    if (!trimmed || trimmed.startsWith('default ') || trimmed.startsWith('else')) continue

    const block = trimmed.match(HEAD_BLOCK) ?? trimmed.match(HEAD_BLOCK_V0)
    if (block) {
      const close = findClose(lines, i)
      if (close === -1) continue
      const body = lines.slice(i + 1, close).join('\n')
      push(block[1], i + 1, body, `{\n${body}\n}`)
      i = close
      continue
    }

    const inline = trimmed.match(HEAD_INLINE)
    if (inline && !inline[2].includes('{')) {
      push(inline[1], i + 1, inline[2], `{\n    ${inline[2]}\n}`)
    }
  }

  function push(name: string, line: number, body: string, block: string) {
    const id = `__ds_${rules.length}`
    rules.push({ id, name, line, body: body.trim() })
    synthetic.push(`${id} if ${block}`)
  }

  const source = synthetic.length
    ? `${policy}\n\n# --- decision-surface instrumentation ---\n${synthetic.join('\n\n')}\n`
    : policy
  return { source, rules }
}

/** Index of the line closing a rule block opened at `open`. */
function findClose(lines: string[], open: number): number {
  let depth = 0
  for (let i = open; i < lines.length; i++) {
    for (const ch of lines[i]) {
      if (ch === '{') depth++
      else if (ch === '}') depth--
    }
    if (depth === 0 && i > open) return i
    if (depth === 0 && i === open) return -1
  }
  return -1
}
