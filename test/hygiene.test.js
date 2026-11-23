import test from 'node:test'; import assert from 'node:assert'; import fs from 'node:fs'; import path from 'node:path'; import { fileURLToPath } from 'node:url';
const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
function files(dir) { return fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => { const p = path.join(dir, e.name); if (e.isDirectory()) return ['node_modules', '.git', 'vendor', '.venv', 'dist', 'build', '__pycache__', '.pytest_cache', '.tectonic-cache'].includes(e.name) ? [] : files(p); return /\.(js|mjs|cjs|ts|html|css|md|json|jsonl|yml|yaml|webmanifest|svg|txt|py|toml|tex|bib|cff|cfg)$/.test(e.name) ? [p] : []; }); }
test('public files carry no numbering labels, real-looking keys or non-example addresses', () => {
  const list = files(ROOT); assert.ok(list.length > 20);
  for (const f of list) {
    if (f.endsWith('hygiene.test.js')) continue;
    const s = fs.readFileSync(f, 'utf8');
    assert.doesNotMatch(s, /\bproject\s+\d+\b|\bof 15\b|\bpart \d+ of\b|\bfinal project\b|\b15[- ]part\b/i, f);
    assert.doesNotMatch(s, /\bF-1\b|\bvisa\b|\bimmigra|\bgreen card\b/i, f);
    assert.doesNotMatch(s, /\bO-1\b|\bEB-1\b|\bH-1B\b/, f);
    assert.doesNotMatch(s, /\bseries\b/i, f);
    assert.doesNotMatch(s, /\bsk-(proj-|ant-)?[A-Za-z0-9]{32,}|AIza[0-9A-Za-z_-]{35}|ghp_[A-Za-z0-9]{36}\b|xox[bp]-\d{6,}/, f);
    for (const m of (s.match(/[\w.+-]+@[\w-]+(?:\.[\w-]+)+/g) || []).map((x) => x.toLowerCase())) assert.ok(/\.example$|noreply\.github\.com$|^git@github\.com$|@\d|@[\w-]+\.(js|mjs|css)$|^[\w.-]+@v?\d/.test(m), f + ': ' + m);
  }
});
