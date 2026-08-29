import { useEffect, useMemo, useRef, useState } from 'react'
import fixture from './fixtures/authz.rego?raw'
import { loadPolicy, evaluate, type EvalResult } from './opa'
import { extractFields, type Field, type Value } from './extract'

type Kind = 'true' | 'false' | 'empty' | 'nonempty' | 'error'
type Cell = { kind: Kind; title: string }

export default function App() {
  const [policy, setPolicy] = useState(fixture)
  const [entrypoint, setEntrypoint] = useState('data.authz.allow')
  const [xPath, setXPath] = useState('')
  const [yPath, setYPath] = useState('')
  const [pinned, setPinned] = useState<Record<string, number>>({})
  const [grid, setGrid] = useState<Cell[][]>([])
  const [status, setStatus] = useState('')

  const fields = useMemo(() => extractFields(policy), [policy])
  const xField = fields.find((f) => f.path === xPath)
  const yField = fields.find((f) => f.path === yPath)

  // Keep the axis selections pointing at fields that still exist.
  useEffect(() => {
    if (!fields.some((f) => f.path === xPath)) setXPath(fields[0]?.path ?? '')
    if (!fields.some((f) => f.path === yPath)) setYPath(fields[1]?.path ?? '')
  }, [fields, xPath, yPath])

  const held = fields.filter((f) => f.path !== xPath && f.path !== yPath)

  // Re-sweep on any change, debounced so typing in the policy box is bearable.
  const runId = useRef(0)
  useEffect(() => {
    if (!xField || !yField) return
    const id = ++runId.current
    const t = setTimeout(async () => {
      setStatus('evaluating…')
      const loadErr = await loadPolicy(policy)
      if (id !== runId.current) return
      if (loadErr) {
        setGrid([])
        setStatus(loadErr)
        return
      }

      const rows = await Promise.all(
        yField.values.map((yv) =>
          Promise.all(
            xField.values.map(async (xv) => {
              const input = buildInput(fields, pinned, [xField.path, xv], [yField.path, yv])
              const res = await evaluate(entrypoint, input)
              return toCell(input, res)
            }),
          ),
        ),
      )
      if (id !== runId.current) return
      setGrid(rows)
      setStatus(`${rows.length * (rows[0]?.length ?? 0)} evaluations`)
    }, 250)
    return () => clearTimeout(t)
  }, [policy, entrypoint, xPath, yPath, pinned, fields, xField, yField])

  return (
    <main>
      <h1>Decision Surface</h1>

      <div className="cols">
        <label>
          policy
          <textarea value={policy} onChange={(e) => setPolicy(e.target.value)} rows={16} />
        </label>
        <div className="controls">
          <label>
            entrypoint
            <input value={entrypoint} onChange={(e) => setEntrypoint(e.target.value)} />
          </label>
          <label>
            X axis
            <select value={xPath} onChange={(e) => setXPath(e.target.value)}>
              {fields.map((f) => <option key={f.path} value={f.path}>{f.path}</option>)}
            </select>
          </label>
          <label>
            Y axis
            <select value={yPath} onChange={(e) => setYPath(e.target.value)}>
              {fields.map((f) => <option key={f.path} value={f.path}>{f.path}</option>)}
            </select>
          </label>
          {held.map((f) => (
            <label key={f.path}>
              {f.path} <span className="dim">(held)</span>
              <select
                value={pinned[f.path] ?? 0}
                onChange={(e) => setPinned({ ...pinned, [f.path]: Number(e.target.value) })}
              >
                {f.values.map((v, i) => <option key={i} value={i}>{showValue(v)}</option>)}
              </select>
            </label>
          ))}
          <div className="status">{status}</div>
        </div>
      </div>

      {xField && yField && grid.length > 0 && (
        <>
          <div className="axis-name">x: {xField.path} &nbsp; y: {yField.path}</div>
          <table className="grid">
            <thead>
              <tr>
                <th />
                {xField.values.map((v, i) => <th key={i}>{showValue(v)}</th>)}
                <th />
              </tr>
            </thead>
            <tbody>
              {grid.map((row, ri) => (
                <tr key={ri}>
                  <th>{showValue(yField.values[ri])}</th>
                  {row.map((cell, ci) => (
                    <td key={ci} className={`cell ${cell.kind}`} title={cell.title} />
                  ))}
                  <th>{showValue(yField.values[ri])}</th>
                </tr>
              ))}
            </tbody>
            <tfoot>
              <tr>
                <th />
                {xField.values.map((v, i) => <th key={i}>{showValue(v)}</th>)}
                <th />
              </tr>
            </tfoot>
          </table>
          <div className="legend">
            <span className="cell true" /> true
            <span className="cell false" /> false / undefined
            <span className="cell empty" /> empty set
            <span className="cell nonempty" /> non-empty set
            <span className="cell error" /> error
          </div>
        </>
      )}

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

/** Set input.a.b -> { a: { b: value } }. An undefined value means "absent". */
function setPath(obj: Record<string, any>, path: string, value: Value) {
  if (value === undefined) return
  const parts = path.replace(/^input\./, '').split('.')
  let cur = obj
  for (const part of parts.slice(0, -1)) {
    if (typeof cur[part] !== 'object' || cur[part] === null) cur[part] = {}
    cur = cur[part]
  }
  cur[parts[parts.length - 1]] = value
}

function buildInput(
  fields: Field[],
  pinned: Record<string, number>,
  x: [string, Value],
  y: [string, Value],
): Record<string, unknown> {
  const input: Record<string, any> = {}
  for (const f of fields) {
    if (f.path === x[0] || f.path === y[0]) continue
    setPath(input, f.path, f.values[pinned[f.path] ?? 0])
  }
  setPath(input, x[0], x[1])
  setPath(input, y[0], y[1])
  return input
}

function toCell(input: unknown, res: EvalResult): Cell {
  const kind = classify(res)
  const shown = res.ok ? (res.value === undefined ? 'undefined' : JSON.stringify(res.value)) : res.error
  return { kind, title: `${JSON.stringify(input, null, 2)}\n\n=> ${shown}` }
}

function classify(res: EvalResult): Kind {
  if (!res.ok) return 'error'
  const v = res.value
  if (v === true) return 'true'
  if (v === false || v === undefined || v === null) return 'false'
  if (Array.isArray(v)) return v.length ? 'nonempty' : 'empty'
  if (typeof v === 'object') return Object.keys(v as object).length ? 'nonempty' : 'empty'
  return 'nonempty'
}

export function showValue(v: Value): string {
  return v === undefined ? '<absent>' : typeof v === 'string' ? v : JSON.stringify(v)
}
