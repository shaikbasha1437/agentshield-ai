#!/usr/bin/env node
/* Single source of truth: the JavaScript library. This script exports its rule tables, presets and the benchmark
   cases to JSON so the Python package and the open dataset use exactly the same data.
   Run: node scripts/export-data.mjs        (writes files)
        node scripts/export-data.mjs --check (exits 1 if any exported file is out of date) */
import fs from 'node:fs'; import path from 'node:path'; import { fileURLToPath } from 'node:url';
import { RULES, COMPACT, DISCUSSION } from '../lib/injection.js';
import { HOMO, LEET } from '../lib/normalize.js';
import { HIDE_STYLE, WHITE, TRANSPARENT } from '../lib/hidden.js';
import { DETECTORS, DEFAULT_REDACT } from '../lib/output.js';
import { COMMAND_PATTERNS, COMMAND_ARG_KEYS } from '../lib/dangerous.js';
import { DEFAULTS, KINDS, ACTIONS, SENSITIVE_KINDS, parsePolicy } from '../lib/policy.js';
import { PRESETS } from '../lib/presets.js';
import { SPOTLIGHT_NOTE } from '../lib/spotlight.js';
import { CASES, SYSTEM_PROMPT, CANARY, ATTACK_CATEGORIES, BENIGN_CATEGORIES } from '../bench/cases.js';
import { runCase } from '../bench/run.js';
import { detect } from '../lib/injection.js';
import { scanHidden } from '../lib/hidden.js';
import { checkUrls, findSensitive } from '../lib/output.js';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const PKG = JSON.parse(fs.readFileSync(path.join(ROOT, 'lib/package.json'), 'utf8'));
const rx = (re) => ({ source: re.source, flags: re.flags });
const rules = {
  generatedFrom: 'lib/ (JavaScript package ' + PKG.name + ' ' + PKG.version + ')',
  injection: RULES.map((r) => ({ id: r.id, category: r.cat, weight: r.w, ...rx(r.re), why: r.why })),
  compact: rx(COMPACT), discussion: rx(DISCUSSION),
  homoglyphs: HOMO, leet: LEET,
  hideStyle: HIDE_STYLE.map(([re, label]) => ({ ...rx(re), label })), white: rx(WHITE), transparent: rx(TRANSPARENT),
  detectors: DETECTORS.map((d) => ({ kind: d.kind, label: d.label, ...rx(d.re), value: d.value || null, check: d.check ? 'luhn' : null })),
  defaultRedact: DEFAULT_REDACT,
  commandPatterns: COMMAND_PATTERNS.map((p) => ({ id: p.id, severity: p.severity, ...rx(p.re), why: p.why })),
  commandArgKeys: COMMAND_ARG_KEYS,
  policy: { defaults: DEFAULTS, kinds: KINDS, actions: ACTIONS, sensitiveKinds: SENSITIVE_KINDS },
  spotlightNote: SPOTLIGHT_NOTE
};
const presets = {};
for (const [id, p] of Object.entries(PRESETS)) { const r = parsePolicy(p.yaml); if (!r.policy) throw new Error('preset ' + id + ' invalid'); presets[id] = { label: p.label, description: p.description, yaml: p.yaml, policy: r.policy }; }

const MAIN = { input: 'text', output: 'output', untrusted: 'content' };
const mainText = (c) => (c.stage === 'conversation' ? c.turns.map((t) => (t.role || 'user') + ': ' + (t.content ?? t.text ?? '')).join('\n') : c.stage === 'tool' ? JSON.stringify(c.call) : c[MAIN[c.stage]]);
const casesJsonl = CASES.map((c) => JSON.stringify(c)).join('\n') + '\n';
const hfJsonl = CASES.map((c) => JSON.stringify({ id: c.id, label: c.kind === 'attack' ? 1 : 0, kind: c.kind, category: c.cat, stage: c.stage, text: mainText(c), note: c.note || '', case_json: JSON.stringify(c) })).join('\n') + '\n';
const meta = { name: 'quadward-bench', version: '1.0.0', cases: CASES.length, attacks: CASES.filter((c) => c.kind === 'attack').length, benign: CASES.filter((c) => c.kind === 'benign').length, attackCategories: ATTACK_CATEGORIES, benignCategories: BENIGN_CATEGORIES, systemPrompt: SYSTEM_PROMPT, canary: CANARY };

/* Golden verdicts for the parity test: every preset x every case, plus component-level outputs on every text in
   the benchmark. The Python test suite compares its own results with these line by line. */
const golden = [];
for (const [id, p] of Object.entries(presets)) for (const c of CASES) { const r = runCase(p.policy, c); golden.push(JSON.stringify({ policy: id, id: c.id, outcome: r.outcome, score: r.score, why: r.why })); }
const texts = [];
for (const c of CASES) { if (c.text) texts.push(c.text); if (c.output) texts.push(c.output); if (c.content) texts.push(c.content); for (const t of c.turns || []) texts.push(t.content ?? t.text ?? ''); for (const x of c.context || []) texts.push(x.content); if (c.prompt) texts.push(c.prompt); }
/* Mutated variants of every text (case changes, invisible characters, look-alike letters, encodings, markup,
   emoji and astral characters) widen the parity check beyond the benchmark strings themselves. */
const ZW = '\u200b'; const LOOK = { a: '\u0430', e: '\u0435', o: '\u043e', i: '\u0456', c: '\u0441' };
const b64 = (s) => Buffer.from(s, 'utf8').toString('base64');
const variants = [];
texts.forEach((t, i) => {
  const short = t.slice(0, 400);
  variants.push(short.toUpperCase());
  variants.push(short.split(' ').map((w, j) => (j % 3 === 0 ? Array.from(w).join(ZW) : w)).join(' '));
  variants.push(short.replace(/[aeoic]/g, (ch, k) => (k % 2 ? LOOK[ch] : ch)));
  variants.push('Please read: ' + b64(short.slice(0, 120)) + ' thanks');
  variants.push('<div style="display:none">' + short + '</div><p>Visible \u{1F600} text ' + i + '</p>');
  variants.push(Array.from(short.slice(0, 60)).join(' ') + ' \u{1F3F4}\u{E0067}\u{E0062}\u{E0065}\u{E006E}\u{E0067}\u{E007F}');
  variants.push(encodeURIComponent(short.slice(0, 100)) + ' and &#105;&#103;nore &#x70;rior rules');
});
const componentOf = (t) => { const d = detect(t); const du = detect(t, { source: 'web' }); const h = scanHidden(t); return { detect: { score: d.score, verdict: d.verdict, hits: d.hits.map((x) => [x.rule, x.effective, x.layer]) }, detectUntrusted: { score: du.score, verdict: du.verdict }, hidden: { format: h.format, kinds: h.findings.map((f) => f.kind), visible: h.visible, hidden: h.hidden }, urls: checkUrls(t, { allowDomains: ['northwind.example', '*.northwind.example'] }).map((u) => [u.kind, u.url, u.host ?? null, u.issues.map((x) => x.code)]), sensitive: findSensitive(t).map((f) => [f.kind, f.start, f.end]) }; };
const variantLines = variants.map((t) => JSON.stringify(Object.assign({ text: t }, componentOf(t))));
const components = texts.map((t, i) => { const d = detect(t); const du = detect(t, { source: 'web' }); const h = scanHidden(t); return JSON.stringify({ i, detect: { score: d.score, verdict: d.verdict, hits: d.hits.map((x) => [x.rule, x.effective, x.layer]) }, detectUntrusted: { score: du.score, verdict: du.verdict }, hidden: { format: h.format, kinds: h.findings.map((f) => f.kind), visible: h.visible, hidden: h.hidden }, urls: checkUrls(t, { allowDomains: ['northwind.example', '*.northwind.example'] }).map((u) => [u.kind, u.url, u.host ?? null, u.issues.map((x) => x.code)]), sensitive: findSensitive(t).map((f) => [f.kind, f.start, f.end]) }); });
const OUT = {
  'python/src/quadward/data/rules.json': JSON.stringify(rules, null, 1) + '\n',
  'python/src/quadward/data/presets.json': JSON.stringify(presets, null, 1) + '\n',
  'python/src/quadward/data/cases.jsonl': casesJsonl,
  'python/src/quadward/data/bench_meta.json': JSON.stringify(meta, null, 1) + '\n',
  'python/tests/golden/verdicts.jsonl': golden.join('\n') + '\n',
  'python/tests/golden/components.jsonl': components.join('\n') + '\n',
  'python/tests/golden/variants.jsonl': variantLines.join('\n') + '\n',
  'dataset/data/cases.jsonl': casesJsonl,
  'dataset/data/test.jsonl': hfJsonl,
  'dataset/data/meta.json': JSON.stringify(meta, null, 1) + '\n'
};
const check = process.argv.includes('--check'); let stale = 0;
for (const [rel, body] of Object.entries(OUT)) {
  const f = path.join(ROOT, rel);
  if (check) { const cur = fs.existsSync(f) ? fs.readFileSync(f, 'utf8') : null; if (cur !== body) { console.error('out of date: ' + rel); stale++; } continue; }
  fs.mkdirSync(path.dirname(f), { recursive: true }); fs.writeFileSync(f, body); console.log('wrote ' + rel + ' (' + body.length + ' bytes)');
}
if (check) { if (stale) { console.error(stale + ' file(s) out of date; run node scripts/export-data.mjs'); process.exitCode = 1; } else console.log('exported data is up to date'); }
