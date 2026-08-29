import { useMemo, useState } from 'react'
import fixture from './fixtures/authz.rego?raw'
import { loadPolicy, evaluate } from './opa'
import { extractFields, type Value } from './extract'

const DEFAULT_INPUT = JSON.stringify(
  { role: 'guest', action: 'read', resource: { confidential: false } },
  null,
  2,
)

export default function App() {
  const [policy, setPolicy] = useState(fixture)
  const [inputText, setInputText] = useState(DEFAULT_INPUT)
  const [entrypoint, setEntrypoint] = useState('data.authz.allow')
  const [output, setOutput] = useState('')

  const fields = useMemo(() => extractFields(policy), [policy])

  async function run() {
    let input: unknown
    try {
      input = JSON.parse(inputText)
    } catch (e) {
      setOutput(`input JSON is not valid:\n${String(e)}`)
      return
    }

    const loadErr = await loadPolicy(policy)
    if (loadErr) {
      setOutput(loadErr)
      return
    }

    const res = await evaluate(entrypoint, input)
    setOutput(
      res.ok
        ? `result: ${JSON.stringify(res.value, null, 2) ?? 'undefined'}`
        : `error:\n${res.error}`,
    )
  }

  return (
    <main>
      <h1>Decision Surface</h1>
      <div className="cols">
        <label>
          policy
          <textarea value={policy} onChange={(e) => setPolicy(e.target.value)} rows={20} />
        </label>
        <label>
          input
          <textarea value={inputText} onChange={(e) => setInputText(e.target.value)} rows={20} />
        </label>
      </div>
      <div className="row">
        <label>
          entrypoint
          <input value={entrypoint} onChange={(e) => setEntrypoint(e.target.value)} />
        </label>
        <button onClick={run}>Evaluate</button>
      </div>
      <pre>{output}</pre>

      <h2>discovered fields ({fields.length})</h2>
      <table className="fields">
        <tbody>
          {fields.map((f) => (
            <tr key={f.path}>
              <td>{f.path}</td>
              <td>{f.type}</td>
              <td>{f.values.map(showValue).join('  ')}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </main>
  )
}

export function showValue(v: Value): string {
  return v === undefined ? '<absent>' : JSON.stringify(v)
}
