/* Policy test runner: runs the tests listed in a policy (or any list you pass) against a fresh guard. */
import { createGuard } from './guard.js';
export function runPolicyTests(policy, tests, o = {}) {
  const list = tests || policy.tests || [];
  return list.map((t, i) => {
    const g = createGuard({ policy, canary: o.canary || 'CANARY-TESTTESTTE', systemPrompt: o.systemPrompt });
    let got; let detail = '';
    try {
      if (t.input != null) { const d = g.checkInput(t.input); got = d.verdict; detail = d.hits.slice(0, 3).map((h) => h.rule).join(', ') || 'no rule hits'; }
      else if (t.untrusted != null) { const r = g.ingest(t.untrusted, { source: t.source || 'web', label: 'test' }); got = r.verdict === 'quarantined' ? 'quarantine' : r.verdict === 'flagged' ? 'flag' : 'allow'; detail = r.removed + ' removed, ' + r.hiddenInstructions.length + ' hidden'; }
      else if (t.output != null) { const r = g.checkOutput(t.output); got = r.action; detail = r.reasons.join('; ') || 'clean'; }
      else if (t.call != null) { if (t.context) g.ingest(t.context, { source: 'web', label: 'context' }); const d = g.checkToolCall(t.call); got = d.action; detail = d.reasons.filter((r) => r.severity !== 'info').map((r) => r.code).join(', ') || 'no issues'; }
      else { got = 'invalid'; detail = 'test has no input, untrusted, output or call'; }
    } catch (e) { got = 'error'; detail = e.message; }
    return { index: i, name: t.name || 'test ' + (i + 1), expect: t.expect, got, pass: got === t.expect, detail };
  });
}
