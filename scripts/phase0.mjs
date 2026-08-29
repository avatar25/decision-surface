// Phase 0: prove the engine. Uploads the fixture policy to a running
// `opa run --server` and evaluates it against a hardcoded input.
import { readFileSync } from 'node:fs';

const OPA = 'http://localhost:8181';
const policy = readFileSync(new URL('../src/fixtures/authz.rego', import.meta.url), 'utf8');

const put = await fetch(`${OPA}/v1/policies/spike`, {
  method: 'PUT',
  headers: { 'Content-Type': 'text/plain' },
  body: policy,
});
if (!put.ok) throw new Error(`policy upload failed: ${await put.text()}`);

const input = { role: 'guest', action: 'read', resource: { confidential: false } };
const res = await fetch(`${OPA}/v1/data/authz/allow`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ input }),
});
const body = await res.json();

console.log('input :', JSON.stringify(input));
console.log('result:', JSON.stringify(body));
console.log(body.result === true ? 'PASS (this is the hole)' : 'FAIL: expected true');
