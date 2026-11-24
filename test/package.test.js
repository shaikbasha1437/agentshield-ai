import test from 'node:test'; import assert from 'node:assert'; import fs from 'node:fs'; import path from 'node:path'; import { fileURLToPath } from 'node:url';
import * as lib from '../lib/index.js';
const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'lib/package.json'), 'utf8'));

test('npm package metadata is complete', () => {
  assert.equal(pkg.name, 'quadward'); assert.equal(pkg.license, 'MIT'); assert.equal(pkg.type, 'module');
  assert.equal(pkg.exports['.'].types, './index.d.ts'); assert.ok(pkg.repository.url.includes('shaikbasha1437/quadward'));
  for (const target of Object.values(pkg.exports)) { const f = typeof target === 'string' ? target : target.default; assert.ok(fs.existsSync(path.join(ROOT, 'lib', f)), f); }
  for (const f of ['README.md', 'CHANGELOG.md', 'LICENSE', 'index.d.ts']) assert.ok(fs.existsSync(path.join(ROOT, 'lib', f)), f);
});

test('package versions agree across npm, Python and the citation file', () => {
  const py = fs.readFileSync(path.join(ROOT, 'python/pyproject.toml'), 'utf8');
  assert.match(py, new RegExp('^version = "' + pkg.version.replace(/\./g, '\\.') + '"', 'm'));
  const init = fs.readFileSync(path.join(ROOT, 'python/src/quadward/__init__.py'), 'utf8');
  assert.match(init, new RegExp('__version__ = "' + pkg.version.replace(/\./g, '\\.') + '"'));
  const cff = path.join(ROOT, 'CITATION.cff');
  if (fs.existsSync(cff)) assert.match(fs.readFileSync(cff, 'utf8'), new RegExp('^version: "?' + pkg.version.replace(/\./g, '\\.'), 'm'));
});

test('index.d.ts declares exactly the runtime exports', () => {
  const d = fs.readFileSync(path.join(ROOT, 'lib/index.d.ts'), 'utf8');
  const declared = new Set([...d.matchAll(/^export (?:declare )?(?:function|const|class) (\w+)/gm)].map((m) => m[1]));
  const runtime = Object.keys(lib);
  assert.deepEqual(runtime.filter((k) => !declared.has(k)), [], 'exported at runtime but not declared');
  assert.deepEqual([...declared].filter((k) => !runtime.includes(k)), [], 'declared but not exported');
});
