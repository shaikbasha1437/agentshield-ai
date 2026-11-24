/* Quadward service worker: network-first with a versioned per-file cache, so updates show up on the
   next online load and the app, the benchmark and the SQL engine still open offline. */
const VERSION = 'quadward-v5';
const FILES = ['./', './index.html', './styles.css', './manifest.webmanifest', './icons/icon.svg', './icons/icon-192.png', './icons/icon-512.png', './vendor/sqljs/sql-wasm.js', './vendor/sqljs/sql-wasm.wasm', './js/agent.js', './js/app.js', './js/llm.js', './js/scenarios.js', './js/store.js', './js/ui.js', './js/webllm.js', './js/world.js', './lib/audit.js', './lib/classifier.js', './lib/dangerous.js', './lib/diff.js', './lib/firewall.js', './lib/guard.js', './lib/hidden.js', './lib/index.js', './lib/injection.js', './lib/normalize.js', './lib/output.js', './lib/policy.js', './lib/presets.js', './lib/sha256.js', './lib/spotlight.js', './lib/taint.js', './lib/testrunner.js', './lib/yaml.js', './bench/cases.js', './bench/report.js', './bench/run.js', './bench/stats.js', './bench/metrics.js'];
self.addEventListener('install', (e) => { e.waitUntil(caches.open(VERSION).then((c) => Promise.all(FILES.map((f) => c.add(new Request(f, { cache: 'reload' })).catch(() => null)))).then(() => self.skipWaiting())); });
self.addEventListener('activate', (e) => { e.waitUntil(caches.keys().then((ks) => Promise.all(ks.filter((k) => (k.startsWith('quadward-') || k.startsWith('agentshield-')) && k !== VERSION).map((k) => caches.delete(k)))).then(() => self.clients.claim())); });
self.addEventListener('fetch', (e) => {
  const req = e.request; if (req.method !== 'GET') return;
  const url = new URL(req.url); if (url.origin !== location.origin) return;
  const key = url.origin + url.pathname;
  e.respondWith(fetch(req).then((res) => { if (res && res.ok && res.type === 'basic') { const copy = res.clone(); caches.open(VERSION).then((c) => c.put(key, copy)); } return res; })
    .catch(() => caches.open(VERSION).then((c) => c.match(key).then((m) => m || (req.mode === 'navigate' ? c.match(new URL('./index.html', self.registration.scope).href) : undefined)).then((m) => m || new Response('Offline and not cached yet.', { status: 503, headers: { 'content-type': 'text/plain' } })))));
});
