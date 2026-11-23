/* Precision, recall and F1, overall and per attack category. This mirrors classification_metrics() in the Python
   package exactly; scripts/eval.mjs and dataset/eval.py print the same tables and CI checks that they agree.

   A case is a positive prediction when the guard intervened (blocked, quarantined, redacted or held for approval:
   the benchmark's "stopped"). Recall for a category is its stop rate. Benign cases have no attack category, so a
   category's false positives are the benign cases run at the same guard stage(s) that the guard intervened on
   (stage-matched precision). Approvals on benign cases count as false positives here, which is stricter than the
   headline false-positive rate (that reports them separately as friction). */
function prf(tp, fp, fn) {
  const precision = tp + fp ? tp / (tp + fp) : NaN; const recall = tp + fn ? tp / (tp + fn) : NaN;
  const f1 = tp === 0 ? (tp + fn ? 0 : NaN) : (2 * precision * recall) / (precision + recall);
  return { tp, fp, fn, precision, recall, f1 };
}
export function classificationMetrics(results) {
  const pos = results.filter((r) => r.kind === 'attack'); const neg = results.filter((r) => r.kind === 'benign');
  const count = (a, f) => a.filter(f).length;
  const overall = prf(count(pos, (r) => r.stopped), count(neg, (r) => r.stopped), count(pos, (r) => !r.stopped));
  const perCategory = [];
  for (const cat of [...new Set(pos.map((r) => r.cat))]) {
    const rs = pos.filter((r) => r.cat === cat); const stages = [...new Set(rs.map((r) => r.stage))].sort();
    const fp = count(neg, (r) => stages.includes(r.stage) && r.stopped);
    perCategory.push(Object.assign(prf(count(rs, (r) => r.stopped), fp, count(rs, (r) => !r.stopped)), { category: cat, n: rs.length, stages, benignAtStages: count(neg, (r) => stages.includes(r.stage)) }));
  }
  return { overall, perCategory };
}
const p1 = (x) => (x == null || Number.isNaN(x) ? 'n/a' : (x * 100).toFixed(1));
export function metricsTable(report) {
  const cm = classificationMetrics(report.results); const a = report.attack; const b = report.benign;
  const lines = [
    'Policy: ' + report.policy + ' (' + report.counts.attacks + ' attacks, ' + report.counts.benign + ' benign)',
    'Attacks stopped: ' + p1(a.stopped.p) + '% [' + p1(a.stopped.lo) + '-' + p1(a.stopped.hi) + ']  False positives: ' + p1(b.falsePositive.p) + '% [' + p1(b.falsePositive.lo) + '-' + p1(b.falsePositive.hi) + ']  Friction: ' + p1(b.friction.p) + '%',
    '',
    '| Category | Stage(s) | n | TP | FN | FP (benign, same stage) | Precision | Recall | F1 |',
    '| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |',
  ];
  for (const m of cm.perCategory) lines.push('| ' + [m.category, m.stages.join(', '), m.n, m.tp, m.fn, m.fp + ' / ' + m.benignAtStages, p1(m.precision), p1(m.recall), p1(m.f1)].join(' | ') + ' |');
  const o = cm.overall;
  lines.push('| ' + ['**all**', 'all', report.counts.attacks, o.tp, o.fn, o.fp + ' / ' + report.counts.benign, p1(o.precision), p1(o.recall), p1(o.f1)].join(' | ') + ' |');
  return lines.join('\n');
}
