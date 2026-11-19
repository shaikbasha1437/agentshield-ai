/* Output guards: secret and PII redaction, system-prompt and canary leak detection, data-exfiltration checks
   on URLs and Markdown images, link allowlisting and JSON-schema enforcement. Pure functions. */
import { stripInvisible } from './normalize.js';

export function luhn(digits) { const d = String(digits).replace(/\D/g, ''); if (d.length < 13 || d.length > 19) return false; let sum = 0; let alt = false; for (let i = d.length - 1; i >= 0; i--) { let n = d.charCodeAt(i) - 48; if (alt) { n *= 2; if (n > 9) n -= 9; } sum += n; alt = !alt; } return sum % 10 === 0; }
/* Ordered so that specific shapes win over generic ones. Each detector: kind, label, re, optional check(match). */
export const DETECTORS = [
  { kind: 'private_key', label: 'private key', re: /-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z]+ )*PRIVATE KEY-----/g },
  { kind: 'api_key', label: 'API key', re: /\b(?:sk-(?:ant-|proj-|or-v1-|svcacct-)?[A-Za-z0-9_-]{16,}|AIza[0-9A-Za-z_-]{30,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[abposr]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|(?:sk|pk|rk)_(?:live|test)_[0-9A-Za-z]{10,}|hf_[A-Za-z0-9]{20,}|glpat-[A-Za-z0-9_-]{20,}|SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}|npm_[A-Za-z0-9]{30,})\b/g },
  { kind: 'jwt', label: 'JSON web token', re: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g },
  { kind: 'secret_assignment', label: 'password or secret value', re: /\b((?:api[_-]?key|secret(?:[_-]?key)?|access[_-]?token|auth[_-]?token|token|password|passwd|pwd|client[_-]?secret|private[_-]?key|db[_-]?pass(?:word)?)\s*[:=]\s*)(["']?)([^\s"'`,;]{6,})\2/gi, value: 3 },
  { kind: 'card', label: 'card number', re: /\b(?:\d[ -]?){12,18}\d\b/g, check: (m) => luhn(m) },
  { kind: 'ssn', label: 'SSN-shaped number', re: /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g },
  { kind: 'email', label: 'email address', re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b/g },
  { kind: 'phone', label: 'phone number', re: /(?<![\w-])(?:\+\d{1,3}[ .-]?)?(?:\(\d{3}\)\s?|\d{3}[ .-])\d{3}[ .-]\d{4}(?![\w-])|(?<![\w])\+(?:4[4-9]|3\d|6\d|9[1-8])[ .-]?\d{2,4}[ .-]?\d{3,4}[ .-]?\d{3,4}(?![\w-])/g },
  { kind: 'iban', label: 'IBAN', re: /\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){3,7}(?: ?[A-Z0-9]{1,3})?\b/g },
  { kind: 'ip', label: 'IP address', re: /\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b/g }
];
export const DEFAULT_REDACT = ['private_key', 'api_key', 'jwt', 'secret_assignment', 'card', 'ssn', 'email', 'phone', 'iban'];
function globToRe(g) { return new RegExp('^' + String(g).toLowerCase().replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*\*/g, '\u0000').replace(/\*/g, '[^@/]*').replace(/\u0000/g, '.*').replace(/\?/g, '.') + '$'); }
export function matchAny(value, patterns) { const v = String(value || '').toLowerCase(); return (patterns || []).some((p) => globToRe(p).test(v)); }
/** Find secrets and personal data. Returns [{ kind, label, start, end, value }]. o.kinds limits the kinds;
 *  o.allowEmails / o.allowDomains exempt addresses you expect in output (e.g. your own support address). */
export function findSensitive(text, o = {}) {
  const s = String(text ?? ''); const kinds = new Set(o.kinds || DEFAULT_REDACT); const out = [];
  const taken = (a, b) => out.some((x) => a < x.end && b > x.start);
  for (const d of DETECTORS) {
    if (!kinds.has(d.kind)) continue; d.re.lastIndex = 0;
    for (const m of s.matchAll(d.re)) {
      let start = m.index; let val = m[0];
      if (d.value) { const pre = m[1] + (m[2] || ''); start = m.index + pre.length; val = m[d.value]; if (/^(?:\*+|x+|\[redacted[^\]]*\]|<[^>]+>|\$\{?\w+\}?|null|none|true|false|changeme|example|your[_-]?\w*)$/i.test(val)) continue; }
      if (d.check && !d.check(val)) continue;
      if (d.kind === 'email' && (matchAny(val, o.allowEmails) || matchAny(val.split('@')[1], o.allowDomains))) continue;
      if (d.kind === 'phone' && val.replace(/\D/g, '').length < 10) continue;
      if (d.kind === 'iban' && !/\d{6}/.test(val.replace(/ /g, ''))) continue;
      const end = start + val.length; if (taken(start, end)) continue;
      out.push({ kind: d.kind, label: d.label, start, end, value: val });
    }
  }
  return out.sort((a, b) => a.start - b.start);
}
export function mask(kind, value) {
  const v = String(value);
  if (kind === 'card') return '[card \u2022\u2022\u2022\u2022' + v.replace(/\D/g, '').slice(-4) + ']';
  if (kind === 'email') { const [u, d] = v.split('@'); return '[email ' + u[0] + '\u2026@' + d + ']'; }
  if (kind === 'phone') return '[phone \u2022\u2022\u2022' + v.replace(/\D/g, '').slice(-2) + ']';
  return '[' + kind.replace(/_/g, ' ') + ' redacted]';
}
/** Redact in place. Returns { text, redactions: [{ kind, label, preview }] } (previews never hold the full value). */
export function redact(text, o = {}) {
  const s = String(text ?? ''); const found = findSensitive(s, o); let out = ''; let pos = 0;
  for (const f of found) { out += s.slice(pos, f.start) + (o.style === 'kind' ? '[' + f.kind + ']' : mask(f.kind, f.value)); pos = f.end; }
  out += s.slice(pos);
  // exact strings the caller registered (e.g. the user's own API keys) are always removed
  for (const sec of o.secrets || []) if (sec && sec.length >= 6) out = out.split(sec).join('[your key redacted]');
  return { text: out, redactions: found.map((f) => ({ kind: f.kind, label: f.label, preview: mask(f.kind, f.value) })) };
}
/* ---------- system prompt and canary leaks ---------- */
export function makeCanary(rand) { const r = rand || Math.random; let s = ''; const A = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; for (let i = 0; i < 10; i++) s += A[Math.floor(r() * A.length)]; return 'CANARY-' + s; }
function words(s) { return stripInvisible(String(s || '')).toLowerCase().normalize('NFKC').replace(/[^\p{L}\p{N}\s]/gu, ' ').split(/\s+/).filter(Boolean); }
/** Did the output reveal the system prompt? Checks canary tokens (also with separators stripped) and 8-word overlaps. */
export function leakCheck(output, o = {}) {
  const out = String(output ?? ''); const findings = [];
  const squashed = out.replace(/[\s\-_.\u200B-\u200D]/g, '').toUpperCase();
  for (const c of o.canaries || []) { if (!c) continue; if (out.includes(c)) findings.push({ kind: 'canary', detail: 'output contains the canary token ' + c.slice(0, 9) + '\u2026' }); else if (squashed.includes(c.replace(/[-_]/g, '').toUpperCase())) findings.push({ kind: 'canary', detail: 'output contains the canary token with separators inserted' }); else if (out.includes(c.split('').reverse().join(''))) findings.push({ kind: 'canary', detail: 'output contains the canary token reversed' }); }
  if (o.systemPrompt) {
    const sp = words(o.systemPrompt); const ow = words(out); const N = 8;
    if (sp.length >= N && ow.length >= N) {
      const grams = new Set(); for (let i = 0; i + N <= sp.length; i++) grams.add(sp.slice(i, i + N).join(' '));
      let hit = 0; const seen = new Set(); for (let i = 0; i + N <= ow.length; i++) { const g = ow.slice(i, i + N).join(' '); if (grams.has(g) && !seen.has(g)) { hit++; seen.add(g); } }
      const coverage = hit / Math.max(1, grams.size);
      if (hit >= 2 || coverage >= 0.25) findings.push({ kind: 'system-prompt', detail: hit + ' eight-word passage(s) of the system prompt appear in the output (' + Math.round(coverage * 100) + '% of it)' });
    }
  }
  return findings;
}
/* ---------- URLs, links, images, exfiltration ---------- */
function entropy(s) { const f = {}; for (const c of s) f[c] = (f[c] || 0) + 1; let h = 0; const n = s.length; for (const k in f) { const p = f[k] / n; h -= p * Math.log2(p); } return h; }
export function extractUrls(text) {
  const s = String(text ?? ''); const out = [];
  for (const m of s.matchAll(/!\[([^\]]*)\]\(\s*<?([^)\s>]+)>?[^)]*\)/g)) out.push({ url: m[2], kind: 'markdown-image', index: m.index, raw: m[0] });
  for (const m of s.matchAll(/(?<!!)\[([^\]]*)\]\(\s*<?([^)\s>]+)>?[^)]*\)/g)) out.push({ url: m[2], kind: 'markdown-link', index: m.index, raw: m[0], text: m[1] });
  for (const m of s.matchAll(/<img\b[^>]*\bsrc\s*=\s*["']?([^"'\s>]+)/gi)) out.push({ url: m[1], kind: 'html-image', index: m.index, raw: m[0] });
  for (const m of s.matchAll(/<a\b[^>]*\bhref\s*=\s*["']?([^"'\s>]+)/gi)) out.push({ url: m[1], kind: 'html-link', index: m.index, raw: m[0] });
  const covered = out.map((u) => [u.index, u.index + u.raw.length]);
  for (const m of s.matchAll(/\b(?:https?|ftp|javascript|data|file):[^\s<>"'`)\]]+/gi)) { if (covered.some(([a, b]) => m.index >= a && m.index < b)) continue; out.push({ url: m[0].replace(/[.,;:!?]+$/, ''), kind: 'bare', index: m.index, raw: m[0] }); }
  return out;
}
export function parseUrl(u) { try { return new URL(u); } catch (e) { return null; } }
export function hostAllowed(host, allow) { return matchAny(String(host || '').replace(/^www\./, ''), allow) || matchAny(host, allow); }
/** Check each URL: scheme, allowlist, look-alike hosts, and data smuggled into the query or path.
 *  Returns [{ url, kind, issues: [{ code, severity: 'block'|'flag', detail }] }]. */
export function checkUrls(text, o = {}) {
  const allow = o.allowDomains || []; const sensitive = o.sensitive || [];
  return extractUrls(text).map((u) => {
    const issues = []; const p = parseUrl(u.url); const add = (code, severity, detail) => issues.push({ code, severity, detail });
    if (!p) { if (/^\w+:/.test(u.url) === false && /^(\/|\.|#)/.test(u.url)) return { ...u, issues }; add('bad-url', 'flag', 'not a valid absolute URL'); return { ...u, issues }; }
    const scheme = p.protocol.replace(':', '');
    if (['javascript', 'data', 'file', 'vbscript'].includes(scheme)) add('unsafe-scheme', 'block', scheme + ': links can run code or read local files');
    const host = p.hostname.toLowerCase();
    if (p.username || p.password || /@/.test(u.url.split('/')[2] || '')) add('userinfo-trick', 'block', 'the part before "@" hides the real host (' + host + ')');
    if (/^\d+\.\d+\.\d+\.\d+$|^\[/.test(host)) add('ip-host', 'flag', 'raw IP address instead of a domain');
    if (/(^|\.)xn--/.test(host)) add('punycode', 'flag', 'internationalised (punycode) host, can imitate another domain');
    const allowed = !allow.length || !host || hostAllowed(host, allow);
    if (!allowed) add(u.kind.endsWith('image') ? 'image-unknown-domain' : 'domain-not-allowed', u.kind.endsWith('image') ? 'block' : (o.linkAction === 'block' ? 'block' : 'flag'), host + ' is not on the allowlist' + (u.kind.endsWith('image') ? '; images load automatically, so their URL can carry data out with no click' : ''));
    const q = (p.search || '') + (p.hash || ''); const path = p.pathname || '';
    const vals = []; for (const [, v] of p.searchParams) vals.push(v); const segs = path.split('/').filter(Boolean);
    const dataLike = vals.concat(segs).filter((v) => v.length >= 24 && entropy(v) >= 3.6 && !/^[a-z-]+$/i.test(v));
    const sens = findSensitive(decodeURIComponentSafe(q + ' ' + path), { kinds: ['api_key', 'jwt', 'card', 'ssn', 'email', 'phone', 'secret_assignment', 'private_key'], allowEmails: o.allowEmails, allowDomains: allow });
    const containsKnown = sensitive.filter((x) => x && x.length >= 4 && decodeURIComponentSafe(u.url).toLowerCase().includes(String(x).toLowerCase()));
    if (sens.length) add('url-carries-sensitive', 'block', 'URL contains ' + Array.from(new Set(sens.map((x) => x.label))).join(', '));
    if (containsKnown.length) add('url-carries-context', 'block', 'URL contains text from the conversation or tools (' + containsKnown.length + ' match' + (containsKnown.length > 1 ? 'es' : '') + ')');
    if (/\{[^}]*\}|%7b/i.test(u.url)) add('templated-url', 'block', 'URL has a {placeholder} for data');
    if (!allowed && (dataLike.length || q.length > 120)) add('url-with-data', 'block', 'query or path carries a long encoded value to an unknown domain');
    return { ...u, host, issues };
  });
}
function decodeURIComponentSafe(s) { try { return decodeURIComponent(String(s).replace(/\+/g, ' ')); } catch (e) { return String(s); } }
/* ---------- JSON schema (subset) ---------- */
export function validateSchema(value, schema, path = '$') {
  const errs = []; if (!schema || typeof schema !== 'object') return errs;
  const t = Array.isArray(value) ? 'array' : value === null ? 'null' : Number.isInteger(value) ? 'integer' : typeof value;
  if (schema.type) { const ok = [].concat(schema.type).some((x) => x === t || (x === 'number' && t === 'integer')); if (!ok) { errs.push(path + ': expected ' + [].concat(schema.type).join('|') + ', got ' + t); return errs; } }
  if (schema.enum && !schema.enum.some((e) => JSON.stringify(e) === JSON.stringify(value))) errs.push(path + ': must be one of ' + schema.enum.map((e) => JSON.stringify(e)).join(', '));
  if (schema.const !== undefined && JSON.stringify(schema.const) !== JSON.stringify(value)) errs.push(path + ': must equal ' + JSON.stringify(schema.const));
  if (typeof value === 'string') { if (schema.maxLength != null && value.length > schema.maxLength) errs.push(path + ': longer than ' + schema.maxLength); if (schema.minLength != null && value.length < schema.minLength) errs.push(path + ': shorter than ' + schema.minLength); if (schema.pattern && !new RegExp(schema.pattern).test(value)) errs.push(path + ': does not match ' + schema.pattern); }
  if (typeof value === 'number') { if (schema.maximum != null && value > schema.maximum) errs.push(path + ': above ' + schema.maximum); if (schema.minimum != null && value < schema.minimum) errs.push(path + ': below ' + schema.minimum); }
  if (t === 'object') {
    for (const k of schema.required || []) if (!(k in value)) errs.push(path + ': missing required "' + k + '"');
    const props = schema.properties || {};
    for (const [k, v] of Object.entries(value)) { if (props[k]) errs.push(...validateSchema(v, props[k], path + '.' + k)); else if (schema.additionalProperties === false) errs.push(path + ': unexpected property "' + k + '"'); }
  }
  if (t === 'array') { if (schema.maxItems != null && value.length > schema.maxItems) errs.push(path + ': more than ' + schema.maxItems + ' items'); if (schema.minItems != null && value.length < schema.minItems) errs.push(path + ': fewer than ' + schema.minItems + ' items'); if (schema.items) value.forEach((v, i) => errs.push(...validateSchema(v, schema.items, path + '[' + i + ']'))); }
  return errs;
}
/** Parse model output as JSON (tolerating a ```json fence) and validate it. Returns { ok, value, errors }. */
export function enforceSchema(text, schema) {
  const s = String(text ?? '').trim(); const m = /^```(?:json)?\s*([\s\S]*?)\s*```$/i.exec(s); const body = m ? m[1] : s;
  let value; try { value = JSON.parse(body); } catch (e) { return { ok: false, value: null, errors: ['output is not valid JSON: ' + e.message.replace(/ in JSON at position \d+.*$/, '')] }; }
  const errors = validateSchema(value, schema); return { ok: !errors.length, value, errors };
}
