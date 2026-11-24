/* Append-only audit log with a SHA-256 hash chain. Each entry stores the hash of the one before it, so editing,
   removing or reordering any entry breaks verification from that point on. Values are redacted (secrets, PII,
   your own keys) before they are written. Tamper-evident, not tamper-proof: whoever holds the whole log can
   rebuild a consistent chain, so export it somewhere you control, or anchor the latest hash elsewhere. */
import { sha256 } from './sha256.js';
import { redact } from './output.js';

export function canonicalJson(v) { if (v === null || typeof v !== 'object') return JSON.stringify(v === undefined ? null : v); if (Array.isArray(v)) return '[' + v.map(canonicalJson).join(',') + ']'; return '{' + Object.keys(v).sort().filter((k) => v[k] !== undefined).map((k) => JSON.stringify(k) + ':' + canonicalJson(v[k])).join(',') + '}'; }
export function redactDeep(v, o = {}) {
  const max = o.maxString ?? 4000;
  if (typeof v === 'string') { const r = redact(v, { secrets: o.secrets, allowEmails: o.allowEmails, kinds: o.kinds }).text; return r.length > max ? r.slice(0, max) + '\u2026 [' + (r.length - max) + ' more characters]' : r; }
  if (Array.isArray(v)) return v.map((x) => redactDeep(x, o));
  if (v && typeof v === 'object') { const out = {}; for (const [k, x] of Object.entries(v)) out[k] = /^(api[_-]?key|key|authorization|password|secret|token)$/i.test(k) && typeof x === 'string' ? '[redacted]' : redactDeep(x, o); return out; }
  return v;
}
export const GENESIS = '0'.repeat(64);
export function entryHash(e) { return sha256([e.prev, e.seq, e.ts, e.type, canonicalJson(e.data)].join('|')); }
export class AuditLog {
  constructor(o = {}) { this.entries = []; this.redact = o.redact !== false; this.secrets = o.secrets || []; this.allowEmails = o.allowEmails || []; this.now = o.now || (() => new Date().toISOString()); this.onAppend = o.onAppend || null; }
  append(type, data) {
    const prev = this.entries.length ? this.entries[this.entries.length - 1].hash : GENESIS;
    const clean = this.redact ? redactDeep(data, { secrets: this.secrets, allowEmails: this.allowEmails }) : JSON.parse(JSON.stringify(data ?? null));
    const e = { seq: this.entries.length + 1, ts: this.now(), type: String(type), data: clean, prev };
    e.hash = entryHash(e); this.entries.push(e); if (this.onAppend) this.onAppend(e); return e;
  }
  verify() { return verifyChain(this.entries); }
  head() { return this.entries.length ? this.entries[this.entries.length - 1].hash : GENESIS; }
  toJSON() { return { format: 'quadward-audit/1', head: this.head(), count: this.entries.length, entries: this.entries }; }
  static from(json, o) { const l = new AuditLog(o); l.entries = (json && json.entries ? json.entries : Array.isArray(json) ? json : []).map((e) => Object.assign({}, e)); return l; }
}
/** Returns { ok, count, brokenAt (seq) , reason }. */
export function verifyChain(entries) {
  let prev = GENESIS;
  for (let i = 0; i < entries.length; i++) {
    const e = entries[i];
    if (e.seq !== i + 1) return { ok: false, count: entries.length, brokenAt: i + 1, reason: 'entry ' + (i + 1) + ' has sequence number ' + e.seq + ' (an entry was removed or reordered)' };
    if (e.prev !== prev) return { ok: false, count: entries.length, brokenAt: e.seq, reason: 'entry ' + e.seq + ' does not point at the hash of entry ' + (e.seq - 1) };
    if (entryHash(e) !== e.hash) return { ok: false, count: entries.length, brokenAt: e.seq, reason: 'entry ' + e.seq + ' was changed after it was written (hash mismatch)' };
    prev = e.hash;
  }
  return { ok: true, count: entries.length, brokenAt: null, reason: entries.length ? 'all ' + entries.length + ' entries chain correctly' : 'the log is empty' };
}
