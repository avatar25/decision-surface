import type { Value } from './extract'

export function showValue(v: Value): string {
  return v === undefined ? '<absent>' : typeof v === 'string' ? v : JSON.stringify(v)
}
