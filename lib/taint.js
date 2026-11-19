/* Taint tracking. Text from untrusted sources (web pages, emails, documents, tool results, RAG chunks) is
   registered with its provenance; text from the user and the system prompt is registered as trusted. When a
   tool call's arguments carry an address, link, domain, account number, path or a long phrase that appeared
   only in untrusted content, that argument is tainted: the call came, at least in part, from data the agent read
   rather than from the person it works for. */
const STOP = new Set(['the', 'a', 'an', 'and', 'or', 'to', 'of', 'in', 'on', 'for', 'is', 'it', 'this', 'that', 'with', 'be', 'are', 'as', 'at', 'by', 'from']);
export function extractEntities(text) {
  const s = String(text ?? ''); const out = new Map(); const add = (kind, v) => { const k = String(v).toLowerCase().replace(/[.,;:!?)\]}'"]+$/, ''); if (k.length >= 3 && !out.has(k)) out.set(k, kind); };
  for (const m of s.matchAll(/\b[\w.%+-]+@[\w-]+(?:\.[\w-]+)+\b/g)) { add('email', m[0]); add('domain', m[0].split('@')[1]); }
  for (const m of s.matchAll(/\bhttps?:\/\/[^\s<>"'`)\]]+/gi)) { add('url', m[0]); try { add('domain', new URL(m[0].replace(/[.,;:!?]+$/, '')).hostname.replace(/^www\./, '')); } catch (e) { /* ignore */ } }
  for (const m of s.matchAll(/\b(?:[a-z0-9-]+\.)+(?:example|com|net|org|io|dev|app|ai|co|xyz|info|biz|ru|cn|tk|top|site|online|link)\b/gi)) add('domain', m[0]);
  for (const m of s.matchAll(/\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){3,7}\b/g)) add('account', m[0].replace(/ /g, ''));
  for (const m of s.matchAll(/\b(?:acct|account|iban|wallet|routing)[\s#:_-]*([A-Za-z0-9-]{6,})\b/gi)) add('account', m[1]);
  for (const m of s.matchAll(/(?:^|[\s"'(=])((?:~|\.{1,2})?\/[\w.@-]+(?:\/[\w.@-]+)+)/g)) add('path', m[1]);
  for (const m of s.matchAll(/(?:\$|usd\s?|eur\s?|€)\s?(\d[\d,]*(?:\.\d{1,2})?)/gi)) { const v = m[1].replace(/,/g, ''); if (Number(v) >= 100) add('amount', v); }
  for (const m of s.matchAll(/`([^`\n]{6,200})`/g)) add('code', m[1].trim());
  return out;
}
export function shingles(text, n = 7) {
  const w = String(text ?? '').toLowerCase().replace(/[^\p{L}\p{N}@.\s-]/gu, ' ').split(/\s+/).filter((x) => x && !STOP.has(x));
  const out = new Set(); for (let i = 0; i + n <= w.length; i++) out.add(w.slice(i, i + n).join(' ')); return out;
}
export class TaintTracker {
  constructor() { this.trustedText = []; this.trusted = new Map(); this.trustedGrams = new Set(); this.sources = []; }
  addTrusted(text) { const s = String(text ?? ''); this.trustedText.push(s); for (const [k, v] of extractEntities(s)) this.trusted.set(k, v); for (const g of shingles(s)) this.trustedGrams.add(g); }
  addUntrusted(text, meta = {}) {
    const s = String(text ?? ''); const id = meta.id || 'src-' + (this.sources.length + 1);
    const src = { id, label: meta.label || id, kind: meta.kind || 'untrusted', entities: extractEntities(s), grams: shingles(s), flagged: !!meta.flagged };
    this.sources.push(src); return src;
  }
  markFlagged(id) { const s = this.sources.find((x) => x.id === id); if (s) s.flagged = true; }
  flaggedSources() { return this.sources.filter((s) => s.flagged); }
  isTrustedValue(v) { const k = String(v).toLowerCase(); if (this.trusted.has(k)) return true; return this.trustedText.some((t) => t.toLowerCase().includes(k)); }
  /** Check one value (string). Returns [{ entity, kind, source, label }]. */
  checkValue(value) {
    const v = String(value ?? ''); if (!v || !this.sources.length) return [];
    const ents = extractEntities(v); const out = [];
    for (const [k, kind] of ents) {
      if (this.isTrustedValue(k)) continue;
      for (const s of this.sources) if (s.entities.has(k)) { out.push({ entity: k, kind, source: s.id, label: s.label }); break; }
    }
    if (v.length >= 40) {
      const g = shingles(v); let n = 0; let src = null;
      for (const x of g) { if (this.trustedGrams.has(x)) continue; const s = this.sources.find((y) => y.grams.has(x)); if (s) { n++; src = src || s; } }
      if (n >= 2) out.push({ entity: n + ' phrase(s) copied from untrusted text', kind: 'phrase', source: src.id, label: src.label });
    }
    if (v.length < 200 && v.trim().length >= 4 && !ents.size) {
      const k = v.trim().toLowerCase();
      if (!this.isTrustedValue(k)) for (const s of this.sources) if (s.entities.has(k)) { out.push({ entity: k, kind: s.entities.get(k), source: s.id, label: s.label }); break; }
    }
    return out;
  }
  /** Check every string inside an args object. Returns [{ arg, entity, kind, source, label }]. */
  checkArgs(args) {
    const out = []; const walk = (v, path) => { if (v == null) return; if (typeof v === 'string' || typeof v === 'number') { for (const t of this.checkValue(String(v))) out.push(Object.assign({ arg: path }, t)); } else if (Array.isArray(v)) v.forEach((x, i) => walk(x, path + '[' + i + ']')); else if (typeof v === 'object') for (const [k, x] of Object.entries(v)) walk(x, path ? path + '.' + k : k); };
    walk(args, ''); return out;
  }
  reset() { this.trustedText = []; this.trusted = new Map(); this.trustedGrams = new Set(); this.sources = []; }
  toJSON() { return { trusted: this.trusted.size, sources: this.sources.map((s) => ({ id: s.id, label: s.label, kind: s.kind, flagged: s.flagged, entities: s.entities.size })) }; }
}
