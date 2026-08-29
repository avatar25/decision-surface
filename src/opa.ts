// Thin client over a local `opa run --server`, proxied at /opa by Vite.

const POLICY_ID = 'spike';

export type EvalResult =
  | { ok: true; value: unknown }
  | { ok: false; error: string };

/** Upload policy source. Returns null on success, or a compile error string. */
export async function loadPolicy(source: string): Promise<string | null> {
  try {
    await clearStalePolicies()
    const res = await fetch(`/opa/v1/policies/${POLICY_ID}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'text/plain' },
      body: source,
    });
    if (res.ok) return null;
    const body = await res.json().catch(() => null);
    return formatOpaError(body) ?? `policy upload failed (${res.status})`;
  } catch (e) {
    return `cannot reach opa server — is \`opa run --server\` running? (${String(e)})`;
  }
}

/**
 * The OPA server keeps every policy ever uploaded, so a leftover copy of the
 * same package (from curl, or an earlier session) collides with ours as
 * "multiple default rules". Drop anything that isn't ours before uploading.
 */
async function clearStalePolicies(): Promise<void> {
  try {
    const res = await fetch('/opa/v1/policies')
    if (!res.ok) return
    const body = await res.json()
    const ids: string[] = (body.result ?? []).map((p: any) => p.id)
    await Promise.all(
      ids
        .filter((id) => id !== POLICY_ID)
        .map((id) => fetch(`/opa/v1/policies/${id}`, { method: 'DELETE' })),
    )
  } catch {
    // Best effort; the upload will surface any real problem.
  }
}

/** Turn "data.authz.allow" into "/opa/v1/data/authz/allow". */
function entrypointUrl(entrypoint: string): string {
  const path = entrypoint.trim().replace(/^data\.?/, '').split('.').filter(Boolean);
  return `/opa/v1/data/${path.join('/')}`;
}

export async function evaluate(entrypoint: string, input: unknown): Promise<EvalResult> {
  try {
    const res = await fetch(entrypointUrl(entrypoint), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ input }),
    });
    const body = await res.json();
    if (!res.ok) return { ok: false, error: formatOpaError(body) ?? `HTTP ${res.status}` };
    // An undefined document comes back as {} with no `result` key.
    return { ok: true, value: 'result' in body ? body.result : undefined };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

function formatOpaError(body: any): string | null {
  if (!body) return null;
  if (Array.isArray(body.errors)) {
    return body.errors
      .map((e: any) => {
        const loc = e.location ? ` (line ${e.location.row})` : '';
        return `${e.code ?? 'error'}: ${e.message}${loc}`;
      })
      .join('\n');
  }
  return body.message ?? null;
}

/** "data.authz.allow" -> { pkg: "data.authz", rule: "allow" } */
export function splitEntrypoint(entrypoint: string): { pkg: string; rule: string } {
  const parts = entrypoint.trim().replace(/^data\.?/, '').split('.').filter(Boolean)
  const rule = parts.pop() ?? 'allow'
  return { pkg: `data.${parts.join('.')}`, rule }
}

export type PackageResult =
  | { ok: true; doc: Record<string, unknown> }
  | { ok: false; error: string }

/**
 * Evaluate a whole package document in one request. With the instrumented
 * policy loaded this yields both the decision and which rules fired.
 */
export async function evaluatePackage(pkg: string, input: unknown): Promise<PackageResult> {
  try {
    const path = pkg.replace(/^data\.?/, '').split('.').filter(Boolean).join('/')
    const res = await fetch(`/opa/v1/data/${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ input }),
    })
    const body = await res.json()
    if (!res.ok) return { ok: false, error: formatOpaError(body) ?? `HTTP ${res.status}` }
    return { ok: true, doc: (body.result ?? {}) as Record<string, unknown> }
  } catch (e) {
    return { ok: false, error: String(e) }
  }
}
