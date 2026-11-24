/* Benchmark runner: runs every case through a fresh guard for the given policy, records what each guard did
   and how long it took, and aggregates stop rates, false positives and friction with 95% Wilson intervals.
   "Stopped" means the attack did not get through as intended: blocked, held for a person's approval, quarantined
   (removed before the model saw it) or redacted. Flag-only results are reported but do not count as stopped. */
import { createGuard } from '../lib/guard.js';
import { recordCall } from '../lib/firewall.js';
import { CASES, SYSTEM_PROMPT, CANARY } from './cases.js';
import { wilson, percentile, mean, mcnemar } from './stats.js';

const STOP = new Set(['blocked', 'approval', 'quarantined', 'redacted']);
const FP = new Set(['blocked', 'quarantined', 'redacted']);
const clock = () => (typeof performance !== 'undefined' ? performance.now() : Date.now());
export function runCase(policy, c) {
  const g = createGuard({ policy, systemPrompt: SYSTEM_PROMPT, canary: CANARY, rand: () => 0.42 });
  const t = {}; const time = (k, fn) => { const t0 = clock(); const r = fn(); t[k] = (t[k] || 0) + (clock() - t0); return r; };
  let outcome = 'passed'; const why = []; let score = null;
  try {
    if (c.prompt) g.trust(c.prompt);
    if (c.stage === 'input') { const d = time('input', () => g.checkInput(c.text, { trust: false })); score = d.score; outcome = d.action === 'block' ? 'blocked' : d.action === 'flag' ? 'flagged' : 'passed'; why.push(...d.hits.slice(0, 4).map((h) => h.rule + (h.layer !== 'text' ? '@' + h.layer : ''))); }
    else if (c.stage === 'conversation') { const d = time('input', () => g.checkConversation(c.turns)); score = d.score; outcome = d.action === 'block' ? 'blocked' : d.action === 'flag' ? 'flagged' : 'passed'; why.push(...d.hits.slice(0, 4).map((h) => h.rule)); if (d.splitAcrossTurns) why.push('split across turns'); }
    else if (c.stage === 'untrusted') {
      const r = time('untrusted', () => g.ingest(c.content, { source: c.source, label: c.label, format: c.format })); score = r.score;
      if (r.verdict === 'quarantined') { outcome = 'quarantined'; why.push(r.removed ? r.removed + ' passage(s) removed' : 'hidden text removed'); } else if (r.verdict === 'flagged') { outcome = 'flagged'; }
      why.push(...r.hits.slice(0, 3).map((h) => h.rule)); if (r.hiddenInstructions.length) why.push('hidden: ' + r.hiddenInstructions.map((h) => h.kind).join(', '));
      if (c.call) { const d = time('tool', () => g.checkToolCall(c.call, { log: false })); const o = d.action === 'deny' ? 'blocked' : d.action === 'require-approval' ? 'approval' : null; if (o) { outcome = o === 'blocked' || outcome !== 'blocked' ? (o === 'blocked' ? 'blocked' : (outcome === 'quarantined' ? 'quarantined' : 'approval')) : outcome; why.push(c.call.tool + ': ' + d.reasons.filter((x) => x.severity !== 'info').map((x) => x.code).join(', ')); } }
    }
    else if (c.stage === 'output') { const r = time('output', () => g.checkOutput(c.output, { systemPrompt: SYSTEM_PROMPT })); outcome = r.action === 'block' ? 'blocked' : r.action === 'redact' ? 'redacted' : r.urls.length ? 'flagged' : 'passed'; why.push(...r.reasons); for (const u of r.urls) why.push((u.host || u.url).slice(0, 40) + ': ' + u.issues.map((i) => i.code).join(', ')); }
    else if (c.stage === 'tool') {
      for (const ctx of c.context || []) g.ingest(ctx.content, { source: ctx.source, label: ctx.label });
      for (const b of c.before || []) { const d = g.checkToolCall(b, { log: false }); if (d.action === 'allow') recordCall(g.state, d); }
      const d = time('tool', () => g.checkToolCall(c.call, { log: false })); outcome = d.action === 'deny' ? 'blocked' : d.action === 'require-approval' ? 'approval' : 'passed'; why.push(...d.reasons.filter((x) => x.severity !== 'info').map((x) => x.code));
    }
  } catch (e) { outcome = 'error'; why.push(e.message); }
  const stopped = STOP.has(outcome); const ms = Object.values(t).reduce((s, x) => s + x, 0);
  return { id: c.id, kind: c.kind, cat: c.cat, stage: c.stage, outcome, stopped, fp: c.kind === 'benign' && FP.has(outcome), friction: c.kind === 'benign' && outcome === 'approval', flagged: outcome === 'flagged', score, why: Array.from(new Set(why)).slice(0, 8), ms, timings: t, note: c.note };
}
export async function runBenchmark(policy, o = {}) {
  const cases = o.cases || CASES; const results = []; const t0 = clock();
  for (let i = 0; i < cases.length; i++) { results.push(runCase(policy, cases[i])); if (o.onProgress && (i % 20 === 19 || i === cases.length - 1)) { o.onProgress(i + 1, cases.length); await new Promise((r) => setTimeout(r, 0)); } }
  return summarize(results, { policy: policy.name, ms: clock() - t0 });
}
export function runBenchmarkSync(policy, o = {}) { const cases = o.cases || CASES; const t0 = clock(); return summarize(cases.map((c) => runCase(policy, c)), { policy: policy.name, ms: clock() - t0 }); }
export function summarize(results, meta = {}) {
  const atk = results.filter((r) => r.kind === 'attack'); const ben = results.filter((r) => r.kind === 'benign');
  const cnt = (a, f) => a.filter(f).length;
  const rate = (k, n) => Object.assign({ k, n }, wilson(k, n));
  const cats = {};
  for (const r of results) { const c = cats[r.cat] = cats[r.cat] || { cat: r.cat, kind: r.kind, n: 0, stopped: 0, blocked: 0, approval: 0, quarantined: 0, redacted: 0, flagged: 0, passed: 0, fp: 0, friction: 0, error: 0 }; c.n++; c[r.outcome] = (c[r.outcome] || 0) + 1; if (r.stopped) c.stopped++; if (r.fp) c.fp++; if (r.friction) c.friction++; }
  const categories = Object.values(cats).map((c) => Object.assign(c, c.kind === 'attack' ? { rate: rate(c.stopped, c.n) } : { fpRate: rate(c.fp, c.n), frictionRate: rate(c.friction, c.n) }));
  const stages = {}; for (const r of results) for (const [k, v] of Object.entries(r.timings)) (stages[k] = stages[k] || []).push(v);
  const latency = Object.entries(stages).map(([stage, v]) => ({ stage, n: v.length, meanMs: mean(v), p50Ms: percentile(v, 50), p95Ms: percentile(v, 95), maxMs: Math.max(...v) }));
  const gaps = atk.filter((r) => !r.stopped).map((r) => ({ id: r.id, cat: r.cat, outcome: r.outcome, note: r.note, why: r.why }));
  const fps = ben.filter((r) => r.fp || r.friction).map((r) => ({ id: r.id, cat: r.cat, outcome: r.outcome, note: r.note, why: r.why, friction: r.friction }));
  return {
    format: 'quadward-benchmark/1', policy: meta.policy || 'policy', createdAt: new Date().toISOString(), totalMs: meta.ms ?? null,
    counts: { cases: results.length, attacks: atk.length, benign: ben.length },
    attack: { stopped: rate(cnt(atk, (r) => r.stopped), atk.length), blocked: rate(cnt(atk, (r) => r.outcome === 'blocked'), atk.length), approval: rate(cnt(atk, (r) => r.outcome === 'approval'), atk.length), flaggedOnly: cnt(atk, (r) => r.outcome === 'flagged'), passed: cnt(atk, (r) => r.outcome === 'passed') },
    benign: { falsePositive: rate(cnt(ben, (r) => r.fp), ben.length), friction: rate(cnt(ben, (r) => r.friction), ben.length), flagged: cnt(ben, (r) => r.outcome === 'flagged'), clean: cnt(ben, (r) => r.outcome === 'passed') },
    categories, latency, gaps, falsePositives: fps, results
  };
}
/** Compare two reports on the same cases: McNemar on attack outcomes and on benign false positives. */
export function compareReports(a, b) {
  const map = new Map(b.results.map((r) => [r.id, r]));
  let onlyA = 0; let onlyB = 0; let fpA = 0; let fpB = 0; const changed = [];
  for (const r of a.results) { const s = map.get(r.id); if (!s) continue; if (r.kind === 'attack') { if (r.stopped && !s.stopped) { onlyA++; changed.push({ id: r.id, cat: r.cat, a: r.outcome, b: s.outcome }); } if (!r.stopped && s.stopped) { onlyB++; changed.push({ id: r.id, cat: r.cat, a: r.outcome, b: s.outcome }); } } else { if (r.fp && !s.fp) fpA++; if (!r.fp && s.fp) fpB++; } }
  return { a: a.policy, b: b.policy, attacks: mcnemar(onlyA, onlyB), falsePositives: mcnemar(fpA, fpB), stopDiff: b.attack.stopped.p - a.attack.stopped.p, fpDiff: b.benign.falsePositive.p - a.benign.falsePositive.p, changed };
}
/** Regression gate for CI: compares a report with a baseline. */
export function gate(report, baseline, o = {}) {
  const tol = o.tolerance ?? 0.02; const problems = [];
  if (o.minStopRate != null && report.attack.stopped.p < o.minStopRate) problems.push('attack stop rate ' + pctx(report.attack.stopped.p) + ' is below the minimum ' + pctx(o.minStopRate));
  if (o.maxFalsePositiveRate != null && report.benign.falsePositive.p > o.maxFalsePositiveRate) problems.push('false positive rate ' + pctx(report.benign.falsePositive.p) + ' is above the maximum ' + pctx(o.maxFalsePositiveRate));
  if (baseline) {
    if (report.attack.stopped.p < baseline.attack.stopped.p - tol) problems.push('attack stop rate dropped from ' + pctx(baseline.attack.stopped.p) + ' to ' + pctx(report.attack.stopped.p));
    if (report.benign.falsePositive.p > baseline.benign.falsePositive.p + tol) problems.push('false positive rate rose from ' + pctx(baseline.benign.falsePositive.p) + ' to ' + pctx(report.benign.falsePositive.p));
    const base = new Map((baseline.results || []).map((r) => [r.id, r]));
    const newlyMissed = report.results.filter((r) => r.kind === 'attack' && !r.stopped && base.get(r.id) && base.get(r.id).stopped).map((r) => r.id);
    if (newlyMissed.length && o.failOnNewMiss !== false) problems.push(newlyMissed.length + ' attack case(s) stopped by the baseline now get through: ' + newlyMissed.slice(0, 10).join(', '));
    for (const c of report.categories.filter((x) => x.kind === 'attack')) { const bc = (baseline.categories || []).find((x) => x.cat === c.cat); if (bc && c.rate.p < bc.rate.p - Math.max(tol, 0.1)) problems.push(c.cat + ' stop rate dropped from ' + pctx(bc.rate.p) + ' to ' + pctx(c.rate.p)); }
  }
  return { passed: !problems.length, problems };
}
const pctx = (x) => (x * 100).toFixed(1) + '%';
