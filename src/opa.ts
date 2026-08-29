// Thin client over a local `opa run --server`, proxied at /opa by Vite.

const POLICY_ID = 'spike';

export type EvalResult =
  | { ok: true; value: unknown }
  | { ok: false; error: string };

/** Upload policy source. Returns null on success, or a compile error string. */
export async function loadPolicy(source: string): Promise<string | null> {
  try {
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
