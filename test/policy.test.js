import test from 'node:test'; import assert from 'node:assert';
import { parsePolicy, PRESETS, PRESET_IDS, runPolicyTests, policyToYaml, policyToJson } from '../lib/index.js';
test('every preset parses, validates and passes its own tests', () => {
  assert.equal(PRESET_IDS.length, 8);
  for (const id of PRESET_IDS) { const r = parsePolicy(PRESETS[id].yaml); assert.deepEqual(r.errors, [], id); const t = runPolicyTests(r.policy); assert.ok(t.length >= 1, id); for (const x of t) assert.ok(x.pass, id + ': ' + x.name + ' got ' + x.got); }
});
test('validation errors carry paths and line numbers', () => {
  const r = parsePolicy('version: 1\nmode: loose\ninput:\n  injection: { block: 2 }\ntools:\n  rules:\n    send_email:\n      action: maybe\n      budget: 5\n    x:\n      denyArgs: ["("]\n');
  const msgs = r.errors.map((e) => e.path + '@' + e.line);
  assert.ok(msgs.includes('mode@2')); assert.ok(msgs.includes('input.injection.block@4')); assert.ok(msgs.includes('tools.rules.send_email.action@8')); assert.ok(msgs.includes('tools.rules.send_email.budget@9')); assert.ok(msgs.some((m) => m.startsWith('tools.rules.x.denyArgs[0]')));
  assert.equal(r.policy, null);
  assert.match(parsePolicy('{ "mode": ').errors[0].message, /Invalid JSON/);
  assert.match(parsePolicy('').errors[0].message, /empty/);
  assert.ok(parsePolicy('version: 1\nfoo: 1').warnings.some((w) => /Unknown setting/.test(w.message)));
});
test('YAML and JSON exports parse back to the same policy', () => {
  const p = parsePolicy(PRESETS.strict.yaml).policy;
  assert.deepEqual(parsePolicy(policyToYaml(p)).policy, p); assert.deepEqual(parsePolicy(policyToJson(p)).policy, p);
});
test('the test runner reports failures', () => { const p = parsePolicy(PRESETS.permissive.yaml).policy; const r = runPolicyTests(p, [{ call: { tool: 'run_sql', args: { query: 'DROP TABLE x' } }, expect: 'allow' }]); assert.equal(r[0].pass, false); assert.equal(r[0].got, 'deny'); });
