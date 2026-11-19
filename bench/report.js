/* Report renderers shared by the web app, the CLI and the GitHub Action. */
export const pct = (p) => (p == null || !isFinite(p) ? 'n/a' : (p * 100).toFixed(1) + '%');
export const ci = (r) => pct(r.p) + ' [' + pct(r.lo) + ' to ' + pct(r.hi) + ']';
export const LIMITS = [
  'The cases and the detection rules were written by the same author, so these numbers are optimistic. A fresh attacker who has read the rules will do better than this suite suggests.',
  'Pattern rules catch known phrasings and encodings. Paraphrased or novel attacks, slow multi-turn steering and attacks in languages without rules often get through; the optional LLM classifier helps but is itself attackable.',
  'Spotlighting only helps if the model respects the markers. The tool firewall is the layer that still holds when the model is fooled, so put limits on actions, not just on text.',
  'Data can still leave through allowlisted domains, spelled-out values or channels the guard does not see. Redaction recognises formats (card numbers with a valid checksum, SSN-shaped numbers, key formats), not meaning.',
  'Confidence intervals are 95% Wilson intervals over a small, handwritten suite; they describe this suite, not real traffic.'
];
export function reportToMarkdown(r, o = {}) {
  const L = [];
  L.push('# AgentShield benchmark: ' + r.policy, '', 'Generated ' + r.createdAt + ' over ' + r.counts.cases + ' cases (' + r.counts.attacks + ' attacks, ' + r.counts.benign + ' benign).', '');
  L.push('| Metric | Value (95% CI) |', '| --- | --- |');
  L.push('| Attacks stopped (blocked, held, quarantined or redacted) | ' + ci(r.attack.stopped) + ' |');
  L.push('| Attacks blocked outright | ' + ci(r.attack.blocked) + ' |');
  L.push('| Attacks only flagged | ' + r.attack.flaggedOnly + ' |');
  L.push('| Benign false positives | ' + ci(r.benign.falsePositive) + ' |');
  L.push('| Benign sent for approval (friction) | ' + ci(r.benign.friction) + ' |', '');
  L.push('## By category', '', '| Category | Kind | Cases | Rate (95% CI) |', '| --- | --- | --- | --- |');
  for (const c of r.categories) L.push('| ' + c.cat + ' | ' + c.kind + ' | ' + c.n + ' | ' + (c.kind === 'attack' ? 'stopped ' + ci(c.rate) : 'false positive ' + ci(c.fpRate) + ', friction ' + pct(c.frictionRate.p)) + ' |');
  L.push('', '## Latency per guard (ms)', '', '| Stage | Calls | Mean | p50 | p95 | Max |', '| --- | --- | --- | --- | --- | --- |');
  for (const l of r.latency) L.push('| ' + l.stage + ' | ' + l.n + ' | ' + l.meanMs.toFixed(3) + ' | ' + l.p50Ms.toFixed(3) + ' | ' + l.p95Ms.toFixed(3) + ' | ' + l.maxMs.toFixed(3) + ' |');
  if (o.compare) { const c = o.compare; L.push('', '## Compared with ' + c.a, '', '- Stop rate change: ' + (c.stopDiff >= 0 ? '+' : '') + (c.stopDiff * 100).toFixed(1) + ' points (McNemar p = ' + c.attacks.p.toFixed(3) + ', ' + c.attacks.b + ' stopped only by ' + c.a + ', ' + c.attacks.c + ' only by ' + c.b + ')', '- False positive change: ' + (c.fpDiff >= 0 ? '+' : '') + (c.fpDiff * 100).toFixed(1) + ' points (McNemar p = ' + c.falsePositives.p.toFixed(3) + ')'); }
  if (o.gate) L.push('', '## Gate: ' + (o.gate.passed ? 'passed' : 'FAILED'), '', ...(o.gate.problems.length ? o.gate.problems.map((p) => '- ' + p) : ['- No regressions.']));
  L.push('', '## Known gaps (attacks that got through)', '');
  for (const g of r.gaps) L.push('- **' + g.id + '** (' + g.cat + ', ' + g.outcome + '): ' + (g.note || '') + (g.why.length ? ' Signals: ' + g.why.join('; ') + '.' : ''));
  if (!r.gaps.length) L.push('- None in this suite.');
  L.push('', '## False positives and friction', '');
  for (const f of r.falsePositives) L.push('- **' + f.id + '** (' + f.cat + ', ' + f.outcome + '): ' + (f.note || '') + (f.why.length ? ' Why: ' + f.why.join('; ') + '.' : ''));
  if (!r.falsePositives.length) L.push('- None in this suite.');
  L.push('', '## Limits', '', ...LIMITS.map((x) => '- ' + x), '');
  return L.join('\n');
}
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
export function reportToHtml(r, o = {}) {
  const md = reportToMarkdown(r, o); const out = []; let table = null; let list = false;
  const inline = (s) => esc(s).replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
  const flush = () => { if (table) { out.push('<table>' + table.map((row, i) => '<tr>' + row.map((c) => (i ? '<td>' : '<th>') + inline(c) + (i ? '</td>' : '</th>')).join('') + '</tr>').join('') + '</table>'); table = null; } if (list) { out.push('</ul>'); list = false; } };
  for (const line of md.split('\n')) {
    if (/^\|/.test(line)) { if (/^\|\s*-/.test(line)) continue; (table = table || []).push(line.slice(1, -1).split('|').map((x) => x.trim())); continue; }
    if (/^- /.test(line)) { if (table) flush(); if (!list) { out.push('<ul>'); list = true; } out.push('<li>' + inline(line.slice(2)) + '</li>'); continue; }
    flush();
    const h = /^(#{1,3}) (.*)/.exec(line); if (h) out.push('<h' + h[1].length + '>' + inline(h[2]) + '</h' + h[1].length + '>'); else if (line.trim()) out.push('<p>' + inline(line) + '</p>');
  }
  flush();
  return '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AgentShield benchmark: ' + esc(r.policy) + '</title><style>body{font:15px/1.5 system-ui,sans-serif;max-width:920px;margin:2rem auto;padding:0 1rem;color:#1b1f24}table{border-collapse:collapse;width:100%;margin:.5rem 0 1rem;display:block;overflow-x:auto}th,td{border:1px solid #d0d7de;padding:.35rem .5rem;text-align:left;vertical-align:top}th{background:#f3f5f7}h1{font-size:1.5rem}h2{font-size:1.15rem;margin-top:1.6rem}</style></head><body>' + out.join('\n') + '</body></html>';
}
