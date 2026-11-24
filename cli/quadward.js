#!/usr/bin/env node
/* Quadward CLI: run the attack benchmark against a policy, gate on regressions, validate and test policies,
   and check a single input. Usage: node cli/quadward.js <command> [options]. Runs fully offline. */
import fs from 'node:fs'; import path from 'node:path'; import { fileURLToPath } from 'node:url';
import { parsePolicy, PRESETS, runPolicyTests, detect, createGuard } from '../lib/index.js';
import { runBenchmarkSync, gate, compareReports } from '../bench/run.js';
import { reportToMarkdown, reportToHtml, ci } from '../bench/report.js';

export const HELP = `quadward <command> [options]

  bench     --policy <file|preset> [--baseline report.json] [--min-stop 0.8] [--max-fp 0.1]
            [--tolerance 0.02] [--out report.json] [--md report.md] [--html report.html]
            Runs the built-in attack and benign suite. Exits 1 when the gate fails.
  validate  --policy <file|preset>       Checks a policy file and prints errors with line numbers.
  test      --policy <file|preset>       Runs the tests stored in the policy.
  check     --policy <file|preset> <text>  Scores one input and explains the rule hits.
  presets                              Lists the built-in presets.`;
export function parseArgs(argv) { const o = { _: [] }; for (let i = 0; i < argv.length; i++) { const a = argv[i]; if (a.startsWith('--')) { const k = a.slice(2); const v = argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[++i] : true; o[k] = v; } else o._.push(a); } return o; }
export function loadPolicy(spec, cwd = process.cwd()) {
  if (!spec) spec = 'balanced';
  if (PRESETS[spec]) return { policy: parsePolicy(PRESETS[spec].yaml).policy, errors: [], warnings: [], source: 'preset ' + spec };
  const file = path.resolve(cwd, spec); if (!fs.existsSync(file)) return { policy: null, errors: [{ path: '', line: null, message: 'No preset or file called ' + spec }], warnings: [], source: spec };
  const r = parsePolicy(fs.readFileSync(file, 'utf8')); return Object.assign(r, { source: file });
}
const fmtErr = (e) => (e.line ? 'line ' + e.line + ': ' : '') + (e.path ? e.path + ': ' : '') + e.message;
export function main(argv, io = { out: (s) => process.stdout.write(s + '\n'), err: (s) => process.stderr.write(s + '\n'), cwd: process.cwd() }) {
  const a = parseArgs(argv); const cmd = a._[0];
  if (!cmd || cmd === 'help' || a.help) { io.out(HELP); return 0; }
  if (cmd === 'presets') { for (const [id, p] of Object.entries(PRESETS)) io.out(id.padEnd(16) + p.description); return 0; }
  const lp = loadPolicy(a.policy, io.cwd);
  if (!lp.policy) { io.err('Policy has errors (' + lp.source + '):'); for (const e of lp.errors) io.err('  ' + fmtErr(e)); return 2; }
  for (const w of lp.warnings || []) io.err('warning: ' + fmtErr(w));
  const policy = lp.policy;
  if (cmd === 'validate') { io.out('OK: ' + policy.name + ' (' + Object.keys(policy.tools.rules).length + ' tool rules, mode ' + policy.mode + ')'); return 0; }
  if (cmd === 'test') { const r = runPolicyTests(policy); let bad = 0; for (const t of r) { if (!t.pass) bad++; io.out((t.pass ? 'pass ' : 'FAIL ') + t.name + (t.pass ? '' : ' (expected ' + t.expect + ', got ' + t.got + ')')); } io.out(r.length - bad + '/' + r.length + ' policy tests passed'); return bad ? 1 : 0; }
  if (cmd === 'check') { const text = a._.slice(1).join(' '); const g = createGuard({ policy }); const d = g.checkInput(text); io.out(d.verdict.toUpperCase() + ' score ' + d.score); for (const h of d.hits) io.out('  ' + h.rule + ' [' + h.category + '] +' + h.effective + ' via ' + h.layer + ': ' + h.why); return d.verdict === 'block' ? 1 : 0; }
  if (cmd === 'bench') {
    const report = runBenchmarkSync(policy);
    let baseline = null; if (a.baseline) { try { baseline = JSON.parse(fs.readFileSync(path.resolve(io.cwd, a.baseline), 'utf8')); } catch (e) { io.err('Could not read baseline: ' + e.message); return 2; } }
    const num = (v) => (v == null || v === true || v === '' ? undefined : Number(v));
    const gr = gate(report, baseline, { minStopRate: num(a['min-stop']), maxFalsePositiveRate: num(a['max-fp']), tolerance: num(a.tolerance) });
    const compare = baseline && baseline.results ? compareReports(baseline, report) : null;
    if (a.out) fs.writeFileSync(path.resolve(io.cwd, a.out), JSON.stringify(report, null, 2));
    if (a.md) fs.writeFileSync(path.resolve(io.cwd, a.md), reportToMarkdown(report, { gate: gr, compare }));
    if (a.html) fs.writeFileSync(path.resolve(io.cwd, a.html), reportToHtml(report, { gate: gr, compare }));
    io.out('Policy: ' + policy.name + ' (' + report.counts.attacks + ' attacks, ' + report.counts.benign + ' benign)');
    io.out('Attacks stopped: ' + ci(report.attack.stopped)); io.out('False positives: ' + ci(report.benign.falsePositive)); io.out('Friction: ' + ci(report.benign.friction));
    io.out('Gate: ' + (gr.passed ? 'passed' : 'FAILED')); for (const p of gr.problems) io.out('  - ' + p);
    return gr.passed ? 0 : 1;
  }
  io.err('Unknown command ' + cmd + '\n\n' + HELP); return 2;
}
if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(process.argv[1])) process.exitCode = main(process.argv.slice(2));
