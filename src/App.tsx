import { useEffect, useMemo, useRef, useState } from 'react'
import fixture from './fixtures/authz.rego?raw'
import { loadPolicy, evaluatePackage, splitEntrypoint } from './opa'
import { extractFields, type Value } from './extract'
import { instrument, type RuleDef } from './instrument'
import {
  assignmentToInput,
  buildSankey,
  crossProduct,
  enumeratePaths,
  induceTree,
  mapLimit,
  planSweep,
  type Row,
  type Tree,
} from './analyze'
import { DecisionGraph, Sankey, decisionColor } from './Viz'
import { showValue } from './show'

type View = 'grid' | 'graph' | 'sankey'

export default function App() {
  const [policy, setPolicy] = useState(fixture)
  const [entrypoint, setEntrypoint] = useState('data.authz.allow')
  const [view, setView] = useState<View>('graph')
  const [xPath, setXPath] = useState('')
  const [yPath, setYPath] = useState('')
  const [sankeySource, setSankeySource] = useState('')
  const [rows, setRows] = useState<Row[]>([])
  const [rules, setRules] = useState<RuleDef[]>([])
  const [status, setStatus] = useState('')
  const [detail, setDetail] = useState('')

  const fields = useMemo(() => extractFields(policy), [policy])
  const plan = useMemo(() => planSweep(fields), [fields])
  const paths = plan.fields.map((f) => f.path)

  useEffect(() => {
    if (!paths.includes(xPath)) setXPath(paths[0] ?? '')
    if (!paths.includes(yPath)) setYPath(paths[1] ?? paths[0] ?? '')
    if (!paths.includes(sankeySource)) setSankeySource(paths[0] ?? '')
  }, [paths, xPath, yPath, sankeySource])

  // One sweep over the full cross product feeds all three views.
  const runId = useRef(0)
  useEffect(() => {
    if (plan.fields.length === 0) return
    const id = ++runId.current
    const t = setTimeout(async () => {
      setStatus('evaluating...')
      const { source, rules: found } = instrument(policy)
      const err = await loadPolicy(source)
      if (id !== runId.current) return
      if (err) {
        setRows([])
        setStatus(err)
        return
      }
      setRules(found)

      const { pkg, rule } = splitEntrypoint(entrypoint)
      const combos = crossProduct(plan.fields)
      const started = performance.now()
      const out = await mapLimit(combos, 24, async (assignment): Promise<Row> => {
        const input = assignmentToInput(assignment)
        const res = await evaluatePackage(pkg, input)
        if (!res.ok) return { assignment, input, decision: 'ERROR', fired: [] }
        const value = res.doc[rule]
        return {
          assignment,
          input,
          decision: describe(value),
          fired: found.filter((r) => res.doc[r.id] === true).map((r) => r.id),
        }
      })
      if (id !== runId.current) return
      setRows(out)
      const ms = Math.round(performance.now() - started)
      setStatus(
        `${out.length} evaluations in ${ms}ms` +
          (plan.total < plan.full ? ` (capped from ${plan.full})` : ''),
      )
    }, 250)
    return () => clearTimeout(t)
  }, [policy, entrypoint, plan])

  const valuesOf = useMemo(
    () => new Map(plan.fields.map((f) => [f.path, f.values])),
    [plan],
  )
  const tree = useMemo(
    () => (rows.length ? induceTree(rows, paths, valuesOf) : null),
    [rows, valuesOf],
  )
  const allowPaths = useMemo(
    () => (tree ? enumeratePaths(tree, paths).filter((p) => p.decision === 'ALLOW') : []),
    [tree],
  )
  // Reaching ALLOW on a value the policy never mentions is the sharper signal:
  // it means an unanticipated principal gets in. Breadth holes are softer.
  const unknownValueHoles = allowPaths.filter((p) => p.sentinels.length > 0)
  const breadthHoles = allowPaths.filter((p) => p.sentinels.length === 0 && p.untested.length > 0)
  const sankey = useMemo(
    () => (rows.length && sankeySource ? buildSankey(rows, sankeySource, rules) : null),
    [rows, sankeySource, rules],
  )

  const xField = plan.fields.find((f) => f.path === xPath)
  const yField = plan.fields.find((f) => f.path === yPath)

  return (
    <main>
      <header>
        <h1>Decision Surface</h1>
        <nav>
          {(['graph', 'sankey', 'grid'] as View[]).map((v) => (
            <button key={v} className={view === v ? 'on' : ''} onClick={() => setView(v)}>
              {v}
            </button>
          ))}
        </nav>
      </header>

      <div className="cols">
        <label className="policy-box">
          policy
          <textarea value={policy} onChange={(e) => setPolicy(e.target.value)} rows={18} />
        </label>
        <div className="controls">
          <label>
            entrypoint
            <input value={entrypoint} onChange={(e) => setEntrypoint(e.target.value)} />
          </label>

          {view === 'grid' && (
            <>
              <label>
                X axis
                <select value={xPath} onChange={(e) => setXPath(e.target.value)}>
                  {paths.map((p) => <option key={p} value={p}>{p}</option>)}
                </select>
              </label>
              <label>
                Y axis
                <select value={yPath} onChange={(e) => setYPath(e.target.value)}>
                  {paths.map((p) => <option key={p} value={p}>{p}</option>)}
                </select>
              </label>
              <div className="note">
                Other fields are collapsed: a cell is green if ANY value of them allows.
              </div>
            </>
          )}

          {view === 'sankey' && (
            <label>
              left column
              <select value={sankeySource} onChange={(e) => setSankeySource(e.target.value)}>
                {paths.map((p) => <option key={p} value={p}>{p}</option>)}
              </select>
            </label>
          )}

          <div className="status">{status}</div>
          {rules.length > 0 && (
            <div className="rules">
              {rules.map((r, i) => (
                <div key={r.id} className="rule">
                  <b>R{i + 1}</b> <span className="dim">line {r.line}</span>
                  <pre>{r.body}</pre>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {unknownValueHoles.length > 0 && (
        <div className="lint bad">
          <b>
            {unknownValueHoles.length} route{unknownValueHoles.length > 1 ? 's' : ''} grant ALLOW on a
            value the policy never mentions
          </b>
          {unknownValueHoles.map((h, i) => (
            <div key={i} className="lint-row">
              {routeText(h.tests)}
              {' -> ALLOW '}
              <span className="dim">({h.count} inputs)</span>
            </div>
          ))}
        </div>
      )}

      {breadthHoles.length > 0 && (
        <div className="lint">
          <b>{breadthHoles.length} route{breadthHoles.length > 1 ? 's' : ''} reach ALLOW without testing every field</b>
          {breadthHoles.map((h, i) => (
            <div key={i} className="lint-row">
              {routeText(h.tests)}
              {' -> ALLOW, '}
              <i>never checks {h.untested.map((p) => p.replace(/^input\./, '')).join(', ')}</i>
              <span className="dim"> ({h.count} inputs)</span>
            </div>
          ))}
        </div>
      )}

      {view === 'graph' && tree && (
        <section>
          <h2>decision graph</h2>
          <p className="note">
            Split order is chosen by information gain. A black outline marks a route that
            reaches ALLOW without ever testing every field.
          </p>
          <DecisionGraph
            tree={tree}
            totalFields={paths.length}
            onHoverPath={(node) => setDetail(node ? sampleOf(node) : '')}
          />
          {detail && <pre className="detail">{detail}</pre>}
        </section>
      )}

      {view === 'sankey' && sankey && (
        <section>
          <h2>inputs -&gt; rules -&gt; decision</h2>
          <p className="note">
            Ribbon width is how many swept inputs took that route. Purple means several rules
            fired for the same input, which is redundant overlap.
          </p>
          <Sankey data={sankey} />
        </section>
      )}

      {view === 'grid' && xField && yField && (
        <section>
          <h2>grid: {xField.path} x {yField.path}</h2>
          <Grid rows={rows} xPath={xPath} yPath={yPath} xValues={xField.values} yValues={yField.values} />
        </section>
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

/**
 * Grid over two axes. Every other field is collapsed by asking whether ANY of
 * its values allows, which is the "is this reachable at all" question.
 */
function Grid({
  rows, xPath, yPath, xValues, yValues,
}: {
  rows: Row[]
  xPath: string
  yPath: string
  xValues: Value[]
  yValues: Value[]
}) {
  const key = (a: Value, b: Value) => `${JSON.stringify(a)}|${JSON.stringify(b)}`
  const buckets = new Map<string, Row[]>()
  for (const r of rows) {
    const k = key(r.assignment[xPath], r.assignment[yPath])
    const list = buckets.get(k) ?? []
    list.push(r)
    buckets.set(k, list)
  }

  return (
    <table className="grid">
      <thead>
        <tr>
          <th />
          {xValues.map((v, i) => <th key={i}>{showValue(v)}</th>)}
        </tr>
      </thead>
      <tbody>
        {yValues.map((yv, ri) => (
          <tr key={ri}>
            <th>{showValue(yv)}</th>
            {xValues.map((xv, ci) => {
              const group = buckets.get(key(xv, yv)) ?? []
              const anyAllow = group.some((r) => r.decision === 'ALLOW')
              const allAllow = group.length > 0 && group.every((r) => r.decision === 'ALLOW')
              const cls = group.length === 0 ? 'empty' : anyAllow ? (allAllow ? 'true' : 'partial') : 'false'
              const sample = group[0]
              return (
                <td
                  key={ci}
                  className={`cell ${cls}`}
                  title={
                    sample
                      ? `${JSON.stringify(sample.input, null, 2)}\n\n${group.filter((r) => r.decision === 'ALLOW').length}/${group.length} combinations ALLOW`
                      : 'no data'
                  }
                />
              )
            })}
          </tr>
        ))}
      </tbody>
    </table>
  )
}

function routeText(tests: { path: string; value: Value }[]): string {
  if (!tests.length) return '(any input)'
  return tests.map((t) => `${t.path.replace(/^input\./, '')}=${showValue(t.value)}`).join(' AND ')
}

function describe(value: unknown): string {
  if (value === true) return 'ALLOW'
  if (value === false || value === undefined || value === null) return 'DENY'
  if (Array.isArray(value)) return value.length ? `${value.length} items` : 'empty'
  if (typeof value === 'object') return Object.keys(value as object).length ? 'non-empty' : 'empty'
  return JSON.stringify(value)
}

function sampleOf(node: Tree): string {
  if (node.kind !== 'leaf' || !node.rows.length) return ''
  const r = node.rows[0]
  return `example input (1 of ${node.rows.length}):\n${JSON.stringify(r.input, null, 2)}\n\n=> ${r.decision}`
}

export { decisionColor }
