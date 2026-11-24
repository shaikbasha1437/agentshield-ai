/* GitHub Action entry point (node24). No dependencies: reads INPUT_* variables, runs the benchmark through the
   CLI code, writes the reports, a job summary and outputs, and exits 1 when the gate fails. */
import fs from 'node:fs'; import path from 'node:path';
import { main } from '../cli/quadward.js';
const input = (n) => (process.env['INPUT_' + n.toUpperCase().replace(/ /g, '_')] || process.env['INPUT_' + n.toUpperCase().replace(/[ -]/g, '_')] || '').trim();
export function run(env = process.env, cwd = env.GITHUB_WORKSPACE || process.cwd()) {
  const dir = path.resolve(cwd, input('report-dir') || 'quadward-report'); fs.mkdirSync(dir, { recursive: true });
  const args = ['bench', '--policy', input('policy') || 'balanced', '--out', path.join(dir, 'report.json'), '--md', path.join(dir, 'report.md'), '--html', path.join(dir, 'report.html')];
  if (input('baseline')) args.push('--baseline', input('baseline'));
  if (input('min-stop-rate')) args.push('--min-stop', input('min-stop-rate'));
  if (input('max-false-positive-rate')) args.push('--max-fp', input('max-false-positive-rate'));
  if (input('tolerance')) args.push('--tolerance', input('tolerance'));
  const lines = []; const code = main(args, { out: (s) => { lines.push(s); console.log(s); }, err: (s) => { lines.push(s); console.error(s); }, cwd });
  if (code === 2) { console.log('::error::' + lines.join(' | ')); return code; }
  const report = JSON.parse(fs.readFileSync(path.join(dir, 'report.json'), 'utf8'));
  if (env.GITHUB_OUTPUT) fs.appendFileSync(env.GITHUB_OUTPUT, ['passed=' + (code === 0), 'stop-rate=' + report.attack.stopped.p.toFixed(4), 'false-positive-rate=' + report.benign.falsePositive.p.toFixed(4), 'report=' + path.join(dir, 'report.json')].join('\n') + '\n');
  if (env.GITHUB_STEP_SUMMARY) fs.appendFileSync(env.GITHUB_STEP_SUMMARY, fs.readFileSync(path.join(dir, 'report.md'), 'utf8') + '\n');
  const soft = input('fail-on-gate').toLowerCase() === 'false';
  if (code !== 0) for (const l of lines.filter((x) => x.startsWith('  - '))) console.log((soft ? '::warning' : '::error') + ' title=Guardrails regression::' + l.slice(4));
  if (code === 1 && input('fail-on-gate').toLowerCase() === 'false') { console.log('::warning::The gate failed, but fail-on-gate is false.'); return 0; }
  return code;
}
if (process.env.GITHUB_ACTIONS || process.env.QUADWARD_ACTION_RUN) process.exitCode = run();
