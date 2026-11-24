#!/usr/bin/env node
/* Quadward proxy: a small, self-hostable, OpenAI-compatible endpoint that applies a guardrails policy and then
   forwards the request upstream. No dependencies (node:http and fetch).

   POST /v1/chat/completions   user turn checked, tool messages spotlighted, output redacted, risky tool_calls held
   GET  /v1/models             passed through
   GET  /healthz               liveness and policy name
   Admin routes need QUADWARD_ADMIN_TOKEN, sent as the header "x-quadward-admin: Bearer <token>":
   GET  /guard/audit           redacted, hash-chained audit log
   GET  /guard/approvals       held tool calls
   POST /guard/approvals/:id/approve | /deny   approving lets the identical call through once
   POST /guard/kill            body {"on": true|false}

   Environment: QUADWARD_UPSTREAM (default https://api.openai.com/v1), QUADWARD_POLICY (file or preset),
   QUADWARD_UPSTREAM_KEY (optional; otherwise the caller's Authorization header is forwarded), PORT (8787),
   QUADWARD_ADMIN_TOKEN (admin routes are off when unset). Streaming is not supported; stream:true is refused. */
import http from 'node:http'; import fs from 'node:fs'; import { fileURLToPath } from 'node:url';
import { createGuard, parsePolicy, PRESETS, GuardrailError, canonicalJson, sha256 } from '../lib/index.js';

export function createProxy(o = {}) {
  const upstream = String(o.upstream || 'https://api.openai.com/v1').replace(/\/+$/, '');
  const doFetch = o.fetch || globalThis.fetch;
  const policy = typeof o.policy === 'object' && o.policy ? o.policy : parsePolicy(PRESETS[o.policy || 'balanced'] ? PRESETS[o.policy || 'balanced'].yaml : fs.readFileSync(o.policy, 'utf8')).policy;
  if (!policy) throw new Error('The policy has errors; run "quadward validate" first.');
  const guard = createGuard({ policy, systemPrompt: o.systemPrompt, secrets: o.upstreamKey ? [o.upstreamKey] : [] });
  const approved = new Map(); const held = new Map();
  const sig = (call) => sha256(canonicalJson({ tool: call.tool, args: call.args }));
  const isApproved = (call) => { const k = sig(call); const n = approved.get(k) || 0; if (n > 0) { approved.set(k, n - 1); return true; } return false; };
  const onHeld = (call, d) => { const id = 'apr_' + sig(call).slice(0, 12); if (!held.has(id)) held.set(id, { id, call, reasons: d.reasons, createdAt: new Date().toISOString(), status: 'pending' }); guard.audit.append('approval-requested', { id, tool: call.tool, args: call.args, reasons: d.reasons.map((r) => r.code) }); return id; };
  const send = (res, code, body, headers = {}) => { res.writeHead(code, Object.assign({ 'content-type': 'application/json', 'cache-control': 'no-store' }, headers)); res.end(JSON.stringify(body)); };
  const err = (res, code, message, type = 'guardrails_error', extra = {}) => send(res, code, { error: Object.assign({ message, type }, extra) });
  const isAdmin = (req) => { if (!o.adminToken) return false; const h = String(req.headers['x-quadward-admin'] || ''); return h === 'Bearer ' + o.adminToken; };
  const readBody = (req) => new Promise((resolve, reject) => { let n = 0; const chunks = []; req.on('data', (c) => { n += c.length; if (n > (o.maxBody || 2e6)) { reject(Object.assign(new Error('Request body too large'), { status: 413 })); req.destroy(); } else chunks.push(c); }); req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8'))); req.on('error', reject); });
  const authHeader = (req) => (o.upstreamKey ? 'Bearer ' + o.upstreamKey : req.headers.authorization || '');
  async function chat(req, res) {
    let body; try { body = JSON.parse(await readBody(req) || '{}'); } catch (e) { return err(res, e.status || 400, e.status ? e.message : 'Body is not valid JSON', 'invalid_request_error'); }
    if (body.stream) return err(res, 400, 'Streaming is not supported by the Quadward proxy; send stream: false.', 'invalid_request_error');
    const client = { chat: { completions: { create: async (p) => {
      const r = await doFetch(upstream + '/chat/completions', { method: 'POST', headers: { 'content-type': 'application/json', authorization: authHeader(req) }, body: JSON.stringify(p) });
      const text = await r.text(); let j; try { j = JSON.parse(text); } catch (e) { j = null; }
      if (!r.ok) throw Object.assign(new Error('upstream ' + r.status), { upstreamStatus: r.status, upstreamBody: j || { error: { message: text.slice(0, 500) } } });
      if (!j) throw Object.assign(new Error('upstream returned non-JSON'), { upstreamStatus: 502, upstreamBody: { error: { message: 'Upstream returned a non-JSON body.' } } });
      return j;
    } } } };
    try {
      const out = await guard.wrapOpenAI(client, { onBlock: o.onBlock || 'error', isApproved, onHeld }).chat.completions.create(body);
      return send(res, 200, out, { 'x-quadward-policy': policy.name });
    } catch (e) {
      if (e instanceof GuardrailError) return err(res, 400, 'Blocked by the guard: the message looks like a prompt-injection attempt.', 'guardrails_blocked', { score: e.detail && e.detail.score, rules: e.detail && e.detail.hits.map((h) => h.rule) });
      if (e.upstreamStatus) return send(res, e.upstreamStatus, e.upstreamBody);
      return err(res, 502, 'Could not reach the upstream: ' + e.message, 'upstream_error');
    }
  }
  async function handler(req, res) {
    const url = new URL(req.url, 'http://local'); const p = url.pathname.replace(/\/+$/, '') || '/';
    try {
      if (req.method === 'GET' && p === '/healthz') return send(res, 200, { ok: true, policy: policy.name, mode: guard.policy.mode, killSwitch: !!guard.policy.killSwitch });
      if (req.method === 'POST' && p === '/v1/chat/completions') return await chat(req, res);
      if (req.method === 'GET' && p === '/v1/models') { const r = await doFetch(upstream + '/models', { headers: { authorization: authHeader(req) } }); res.writeHead(r.status, { 'content-type': 'application/json' }); return res.end(await r.text()); }
      if (p.startsWith('/guard/')) {
        if (!isAdmin(req)) return err(res, o.adminToken ? 401 : 403, o.adminToken ? 'Admin token required.' : 'Admin routes are off; set QUADWARD_ADMIN_TOKEN to enable them.', 'auth_error');
        if (req.method === 'GET' && p === '/guard/audit') return send(res, 200, Object.assign(guard.audit.toJSON(), { verify: guard.audit.verify() }));
        if (req.method === 'GET' && p === '/guard/approvals') return send(res, 200, { pending: Array.from(held.values()).filter((h) => h.status === 'pending'), decided: Array.from(held.values()).filter((h) => h.status !== 'pending') });
        const m = /^\/guard\/approvals\/([\w-]+)\/(approve|deny)$/.exec(p);
        if (req.method === 'POST' && m) { const h = held.get(m[1]); if (!h || h.status !== 'pending') return err(res, 404, 'No pending approval ' + m[1], 'not_found'); h.status = m[2] === 'approve' ? 'approved' : 'denied'; h.decidedAt = new Date().toISOString(); if (h.status === 'approved') { const k = sig(h.call); approved.set(k, (approved.get(k) || 0) + 1); } guard.audit.append(h.status === 'approved' ? 'approval-granted' : 'approval-denied', { id: h.id, tool: h.call.tool, by: 'admin' }); return send(res, 200, h); }
        if (req.method === 'POST' && p === '/guard/kill') { let b = {}; try { b = JSON.parse(await readBody(req) || '{}'); } catch (e) { return err(res, 400, 'Body is not valid JSON', 'invalid_request_error'); } return send(res, 200, { killSwitch: guard.kill(b.on !== false) }); }
      }
      return err(res, 404, 'Not found: ' + req.method + ' ' + p, 'not_found');
    } catch (e) { return err(res, 500, 'Proxy error: ' + e.message, 'proxy_error'); }
  }
  const server = http.createServer(handler);
  return { server, handler, guard, held, listen: (port = 8787, host = '127.0.0.1') => new Promise((r) => server.listen(port, host, () => r(server.address()))), close: () => new Promise((r) => server.close(r)) };
}
if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(process.argv[1])) {
  const e = process.env;
  const px = createProxy({ upstream: e.QUADWARD_UPSTREAM, policy: e.QUADWARD_POLICY || 'balanced', upstreamKey: e.QUADWARD_UPSTREAM_KEY, adminToken: e.QUADWARD_ADMIN_TOKEN, systemPrompt: e.QUADWARD_SYSTEM_PROMPT });
  px.listen(Number(e.PORT || 8787), e.HOST || '127.0.0.1').then((a) => console.log('Quadward proxy on http://' + a.address + ':' + a.port + ' -> ' + (e.QUADWARD_UPSTREAM || 'https://api.openai.com/v1') + ' (policy ' + px.guard.policy.name + ')'));
}
