#!/usr/bin/env node
/* Reproducible evaluation of the JavaScript package on the AgentShield benchmark.
   Usage: node scripts/eval.mjs [--preset balanced] [--json]
   Prints, for every preset (or the one given), the headline rates with 95% Wilson intervals and per-category
   precision / recall / F1. dataset/eval.py prints the same tables from the Python package and checks they match. */
import { PRESETS, PRESET_IDS } from '../lib/presets.js';
import { parsePolicy } from '../lib/policy.js';
import { runBenchmarkSync } from '../bench/run.js';
import { metricsTable, classificationMetrics } from '../bench/metrics.js';

const argv = process.argv.slice(2); const json = argv.includes('--json');
const pi = argv.indexOf('--preset'); const ids = pi >= 0 ? [argv[pi + 1]] : PRESET_IDS;
const out = {};
for (const id of ids) {
  if (!PRESETS[id]) { console.error('Unknown preset ' + id + '. Known: ' + PRESET_IDS.join(', ')); process.exit(2); }
  const { policy, errors } = parsePolicy(PRESETS[id].yaml); if (errors.length) throw new Error(id + ': ' + errors[0].message);
  const report = runBenchmarkSync(policy);
  out[id] = { table: metricsTable(report), metrics: classificationMetrics(report.results), outcomes: Object.fromEntries(report.results.map((r) => [r.id, r.outcome])) };
}
if (json) process.stdout.write(JSON.stringify(out) + '\n');
else for (const id of ids) console.log('## ' + id + '\n\n' + out[id].table + '\n');
