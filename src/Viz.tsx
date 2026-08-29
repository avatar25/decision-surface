// Hand-rolled SVG for the decision graph and the Sankey. No chart library.

import type { SankeyData, Tree } from './analyze'
import { showValue } from './show'

const ALLOW = '#4caf50'
const DENY = '#e53935'
const OTHER = '#fb8c00'

export function decisionColor(decision: string): string {
  if (decision === 'ALLOW') return ALLOW
  if (decision === 'DENY') return DENY
  if (decision === 'ERROR') return '#9e9e9e'
  return OTHER
}

// ---------------------------------------------------------------- decision graph

type Placed = {
  node: Tree
  x: number
  y: number
  w: number              // box width, sized to its own label
  label: string          // edge label coming into this node
  parent: Placed | null
  testedCount: number
}

const CHAR_W = 6.6

function boxWidth(text: string): number {
  return Math.max(84, Math.round(text.length * CHAR_W) + 18)
}

const ROW_H = 36
const COL_W = 170

/**
 * Lay the induced tree out left-to-right. Leaves stack down the page and each
 * internal node centres on its children, which keeps routes readable as rows.
 */
function layout(tree: Tree): { nodes: Placed[]; height: number } {
  const nodes: Placed[] = []
  let nextRow = 0

  const place = (node: Tree, depth: number, label: string, parent: Placed | null, tested: number): Placed => {
    if (node.kind === 'leaf') {
      const text = `${node.decision} (${node.count})`
      const p: Placed = {
        node, x: depth * COL_W, y: nextRow * ROW_H, w: boxWidth(text), label, parent, testedCount: tested,
      }
      nextRow++
      nodes.push(p)
      return p
    }
    const self: Placed = {
      node, x: depth * COL_W, y: 0, w: boxWidth(node.path.replace(/^input\./, '')), label, parent, testedCount: tested,
    }
    nodes.push(self)
    const kids = node.children.map((c) =>
      place(c.node, depth + 1, showValue(c.value), self, tested + 1),
    )
    self.y = (kids[0].y + kids[kids.length - 1].y) / 2
    return self
  }

  place(tree, 0, '', null, 0)
  return { nodes, height: nextRow * ROW_H }
}

export function DecisionGraph({
  tree,
  totalFields,
  onHoverPath,
}: {
  tree: Tree
  totalFields: number
  onHoverPath: (rows: Tree | null) => void
}) {
  const { nodes, height } = layout(tree)
  const width = Math.max(...nodes.map((n) => n.x + n.w)) + 190

  return (
    <svg className="viz" width={width} height={height + 40} viewBox={`0 0 ${width} ${height + 40}`}>
      <g transform="translate(10, 20)">
        {nodes.map((n, i) =>
          n.parent ? (
            <g key={`e${i}`}>
              <path
                d={`M ${n.parent.x + n.parent.w} ${n.parent.y} C ${n.parent.x + n.parent.w + 40} ${n.parent.y}, ${n.x - 40} ${n.y}, ${n.x} ${n.y}`}
                fill="none"
                stroke="#bbb"
                strokeWidth={1.5}
              />
              <text x={n.x - 6} y={n.y - 4} className="edge-label" textAnchor="end">
                {n.label}
              </text>
            </g>
          ) : null,
        )}
        {nodes.map((n, i) => {
          if (n.node.kind === 'split') {
            return (
              <g key={`n${i}`}>
                <rect x={n.x} y={n.y - 11} width={n.w} height={22} rx={4} fill="#eceff1" stroke="#90a4ae" />
                <text x={n.x + n.w / 2} y={n.y + 4} className="node-label" textAnchor="middle">
                  {n.node.path.replace(/^input\./, '')}
                </text>
              </g>
            )
          }
          // A route that reaches ALLOW without testing every field is the
          // shape an over-permissive policy has. Mark it.
          const hole = n.node.decision === 'ALLOW' && n.testedCount < totalFields
          return (
            <g
              key={`n${i}`}
              onMouseEnter={() => onHoverPath(n.node)}
              onMouseLeave={() => onHoverPath(null)}
            >
              <rect
                x={n.x}
                y={n.y - 11}
                width={n.w}
                height={22}
                rx={4}
                fill={decisionColor(n.node.decision)}
                stroke={hole ? '#000' : 'none'}
                strokeWidth={hole ? 2 : 0}
              />
              <text x={n.x + n.w / 2} y={n.y + 4} className="node-label light" textAnchor="middle">
                {n.node.decision} ({n.node.count})
              </text>
              {hole && (
                <text x={n.x + n.w + 8} y={n.y + 4} className="hole-flag">
                  never tests {totalFields - n.testedCount} field
                  {totalFields - n.testedCount > 1 ? 's' : ''}
                </text>
              )}
            </g>
          )
        })}
      </g>
    </svg>
  )
}

// ---------------------------------------------------------------- sankey

const SANKEY_H = 320
const NODE_W = 14
const GAP = 6
const LEFT_PAD = 100   // room for the left column's labels
const RIGHT_PAD = 130

export function Sankey({ data, width = 720 }: { data: SankeyData; width?: number }) {
  const total = data.flows.filter((f) => f.from.startsWith('in:')).reduce((n, f) => n + f.count, 0)
  if (!total) return null

  const scale = (SANKEY_H - 40) / total
  const colX = [0, width / 2 - NODE_W / 2, width - NODE_W]

  // Node vertical extents, stacked per column.
  const box = new Map<string, { x: number; y: number; h: number }>()
  data.cols.forEach((col, ci) => {
    let y = 10
    for (const id of col) {
      const size = throughput(data, id)
      const h = Math.max(2, size * scale)
      box.set(id, { x: colX[ci], y, h })
      y += h + GAP
    }
  })

  // Walk flows in node order so ribbons stack without crossing themselves.
  const usedOut = new Map<string, number>()
  const usedIn = new Map<string, number>()
  const ribbons = data.flows
    .slice()
    .sort((a, b) => (box.get(a.from)!.y - box.get(b.from)!.y) || (box.get(a.to)!.y - box.get(b.to)!.y))
    .map((f, i) => {
      const from = box.get(f.from)!
      const to = box.get(f.to)!
      const h = f.count * scale
      const oy = from.y + (usedOut.get(f.from) ?? 0)
      const iy = to.y + (usedIn.get(f.to) ?? 0)
      usedOut.set(f.from, (usedOut.get(f.from) ?? 0) + h)
      usedIn.set(f.to, (usedIn.get(f.to) ?? 0) + h)

      const x0 = from.x + NODE_W
      const x1 = to.x
      const mx = (x0 + x1) / 2
      const d = [
        `M ${x0} ${oy}`,
        `C ${mx} ${oy}, ${mx} ${iy}, ${x1} ${iy}`,
        `L ${x1} ${iy + h}`,
        `C ${mx} ${iy + h}, ${mx} ${oy + h}, ${x0} ${oy + h}`,
        'Z',
      ].join(' ')
      return (
        <path key={i} d={d} fill={ribbonColor(f.to)} opacity={0.35}>
          <title>{`${data.labels.get(f.from)} -> ${data.labels.get(f.to)}: ${f.count}`}</title>
        </path>
      )
    })

  const total_w = width + LEFT_PAD + RIGHT_PAD
  return (
    <svg className="viz" width={total_w} height={SANKEY_H} viewBox={`0 0 ${total_w} ${SANKEY_H}`}>
      <g transform={`translate(${LEFT_PAD}, 0)`}>
        {ribbons}
        {[...box.entries()].map(([id, b]) => {
          // Left column reads outward to the left; the others to the right.
          const leftSide = id.startsWith('in:')
          return (
            <g key={id}>
              <rect x={b.x} y={b.y} width={NODE_W} height={b.h} fill={ribbonColor(id)} />
              <text
                x={leftSide ? b.x - 6 : b.x + NODE_W + 6}
                y={b.y + b.h / 2 + 4}
                className="node-label"
                textAnchor={leftSide ? 'end' : 'start'}
              >
                {data.labels.get(id)}
              </text>
            </g>
          )
        })}
      </g>
    </svg>
  )
}

function throughput(data: SankeyData, id: string): number {
  const out = data.flows.filter((f) => f.from === id).reduce((n, f) => n + f.count, 0)
  const inc = data.flows.filter((f) => f.to === id).reduce((n, f) => n + f.count, 0)
  return Math.max(out, inc)
}

function ribbonColor(id: string): string {
  if (id === 'out:ALLOW') return ALLOW
  if (id === 'out:DENY') return DENY
  if (id.startsWith('out:')) return OTHER
  if (id === 'rule:none') return '#90a4ae'
  if (id.startsWith('rule:') && id.includes('+')) return '#8e24aa'  // overlap
  if (id.startsWith('rule:')) return '#3f8fd0'
  return '#b0bec5'
}
