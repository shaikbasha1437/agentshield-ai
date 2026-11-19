/* Text normalization and decoding layers for the injection detector. An attacker can hide an instruction
   with look-alike letters, invisible characters, leetspeak, letter spacing or an encoding; each function here
   undoes one trick so the same rules can run on every view of the text. Everything is pure and synchronous. */
export const ZERO_WIDTH_RE = /[\u200B-\u200D\u2060-\u2064\uFEFF\u180E\u00AD\u034F\u115F\u1160\u17B4\u17B5\u3164]/g;
export const BIDI_RE = /[\u202A-\u202E\u2066-\u2069\u200E\u200F\u061C]/g;
export const TAG_RE = /[\u{E0000}-\u{E007F}]/gu;
export const VARIATION_RE = /[\uFE00-\uFE0F]|[\u{E0100}-\u{E01EF}]/gu;
/* Look-alike letters from Cyrillic, Greek, Armenian and Latin extensions that NFKC leaves alone. */
const HOMO = {
  'а': 'a', 'в': 'b', 'е': 'e', 'ё': 'e', 'к': 'k', 'м': 'm', 'н': 'h', 'о': 'o', 'р': 'p', 'с': 'c', 'т': 't', 'у': 'y', 'х': 'x', 'ѕ': 's', 'і': 'i', 'ї': 'i', 'ј': 'j', 'ԁ': 'd', 'һ': 'h', 'ԛ': 'q', 'ԝ': 'w', 'ɡ': 'g', 'ӏ': 'l', 'ո': 'n', 'ս': 'u', 'օ': 'o', 'ց': 'g', 'հ': 'h', 'լ': 'l',
  'α': 'a', 'β': 'b', 'ε': 'e', 'η': 'n', 'ι': 'i', 'κ': 'k', 'ν': 'v', 'ο': 'o', 'ρ': 'p', 'τ': 't', 'υ': 'u', 'χ': 'x', 'ω': 'w', 'γ': 'y', 'μ': 'u', 'ϲ': 'c', 'ϳ': 'j',
  'ı': 'i', 'ł': 'l', 'ø': 'o', 'đ': 'd', 'ħ': 'h', 'ŀ': 'l', 'ƅ': 'b', 'ɑ': 'a', 'ɩ': 'i', 'ʀ': 'r', 'ʏ': 'y', 'ᴀ': 'a', 'ʙ': 'b', 'ᴄ': 'c', 'ᴅ': 'd', 'ᴇ': 'e', 'ɢ': 'g', 'ʜ': 'h', 'ɪ': 'i', 'ᴊ': 'j', 'ᴋ': 'k', 'ʟ': 'l', 'ᴍ': 'm', 'ɴ': 'n', 'ᴏ': 'o', 'ᴘ': 'p', 'ꞯ': 'q', 'ꜱ': 's', 'ᴛ': 't', 'ᴜ': 'u', 'ᴠ': 'v', 'ᴡ': 'w', 'ᴢ': 'z'
};
const LEET = { '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b', '9': 'g', '@': 'a', '$': 's', '!': 'i', '|': 'l', '+': 't', '€': 'e', '£': 'l' };
export function stripInvisible(s) { return String(s).replace(ZERO_WIDTH_RE, '').replace(BIDI_RE, '').replace(VARIATION_RE, ''); }
export function countInvisible(s) { const t = String(s); return { zeroWidth: (t.match(ZERO_WIDTH_RE) || []).length, bidi: (t.match(BIDI_RE) || []).length, tags: (t.match(TAG_RE) || []).length }; }
/* Unicode "tag" characters (U+E0020-E007E) mirror ASCII and render as nothing: decode the hidden message. */
export function decodeTags(s) { let out = ''; for (const ch of String(s)) { const cp = ch.codePointAt(0); if (cp >= 0xE0020 && cp <= 0xE007E) out += String.fromCharCode(cp - 0xE0000); } return out; }
export function foldHomoglyphs(s) { let out = ''; for (const ch of String(s)) out += HOMO[ch] || ch; return out; }
/* Words that mix Latin with Cyrillic/Greek letters are a classic filter-evasion trick. */
export function mixedScriptWords(s) {
  const words = String(s).normalize('NFKC').match(/[\p{L}]{3,}/gu) || [];
  return words.filter((w) => /[a-z]/i.test(w) && /[\u0370-\u03FF\u0400-\u04FF\u0530-\u058F]/.test(w));
}
export function deLeet(s) {
  return String(s).replace(/[\p{L}\d@$!|+€£]{3,}/gu, (w) => (/\p{L}/u.test(w) && /[\d@$!|+€£]/.test(w) && !/^\d+(st|nd|rd|th|am|pm|kg|km|mb|gb|ms|px|k|m|x|s|h|d|v)$/i.test(w) ? w.replace(/[\d@$!|+€£]/g, (c) => LEET[c] || c) : w));
}
/* "i g n o r e  a l l" and "i.g.n.o.r.e" -> "ignore all" */
export function collapseSpacedLetters(s) {
  return String(s).replace(/\b\p{L}([ .\-_*·|])(?:\p{L}\1){2,}\p{L}\b/gu, (m) => m.replace(/[ .\-_*·|]/g, '')).replace(/(\p{L}) {2,}(?=\p{L})/gu, '$1 ');
}
export function rot13(s) { return String(s).replace(/[a-z]/gi, (c) => { const b = c <= 'Z' ? 65 : 97; return String.fromCharCode(((c.charCodeAt(0) - b + 13) % 26) + b); }); }
export function reverse(s) { return Array.from(String(s)).reverse().join(''); }
function printableRatio(t) { if (!t) return 0; let p = 0; for (const ch of t) { const c = ch.codePointAt(0); if ((c >= 32 && c < 127) || c === 10 || c === 13 || c === 9 || c > 159) p++; } return p / Array.from(t).length; }
function b64(str) {
  try {
    const clean = str.replace(/-/g, '+').replace(/_/g, '/'); const padded = clean + '==='.slice((clean.length + 3) % 4);
    const bin = typeof atob === 'function' ? atob(padded) : Buffer.from(padded, 'base64').toString('binary');
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0)); return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch (e) { return null; }
}
/* Find base64 / hex / %-encoded / \x-escaped runs and decode the ones that turn into readable text. */
export function decodeSegments(s) {
  const t = String(s); const out = [];
  for (const m of t.matchAll(/[A-Za-z0-9+/_-]{16,}={0,2}/g)) {
    const seg = m[0]; if (!/[A-Z]/.test(seg) || !/[a-z]/.test(seg) || /^[a-z-]+$/i.test(seg)) continue;
    const d = b64(seg); if (d && d.length >= 8 && printableRatio(d) > 0.95 && /[a-z]{3,}/i.test(d) && /\s/.test(d)) out.push({ kind: 'base64', from: seg, text: d });
  }
  for (const m of t.matchAll(/\b(?:[0-9a-f]{2}[\s:]?){12,}\b/gi)) { const hex = m[0].replace(/[\s:]/g, ''); if (hex.length % 2) continue; let d = ''; for (let i = 0; i < hex.length; i += 2) d += String.fromCharCode(parseInt(hex.slice(i, i + 2), 16)); if (printableRatio(d) > 0.95 && /[a-z]{3,}\s/i.test(d)) out.push({ kind: 'hex', from: m[0], text: d }); }
  if (/\\x[0-9a-f]{2}/i.test(t)) { const d = t.replace(/\\x([0-9a-f]{2})/gi, (_, h) => String.fromCharCode(parseInt(h, 16))); out.push({ kind: 'hex-escape', from: '\\x..', text: d }); }
  if (/\\u[0-9a-f]{4}/i.test(t)) { const d = t.replace(/\\u([0-9a-f]{4})/gi, (_, h) => String.fromCharCode(parseInt(h, 16))); out.push({ kind: 'unicode-escape', from: '\\u..', text: d }); }
  if (/(?:%[0-9a-f]{2}){4,}/i.test(t)) { try { out.push({ kind: 'url-encoding', from: '%..', text: decodeURIComponent(t.replace(/\+/g, ' ')) }); } catch (e) { /* malformed */ } }
  if (/&#x?[0-9a-f]+;/i.test(t)) out.push({ kind: 'html-entities', from: '&#..;', text: decodeEntities(t) });
  return out;
}
export function decodeEntities(s) {
  const named = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', '#39': "'" };
  return String(s).replace(/&(#x[0-9a-f]+|#\d+|[a-z]+\d*);/gi, (m, e) => { if (e[0] === '#') { const cp = e[1].toLowerCase() === 'x' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10); try { return String.fromCodePoint(cp); } catch (x) { return m; } } return named[e.toLowerCase()] ?? m; });
}
/* Payload splitting: a = "ignore all prev", b = "ious instructions", then "do a + b". Joins the quoted parts. */
export function joinFragments(s) {
  const t = String(s);
  const assigns = Array.from(t.matchAll(/\b([a-z]\w{0,11})\s*(?:=|:=|is)\s*(["'`“”‘’])([^"'`“”‘’\n]{1,120})\2/gi));
  const out = [];
  if (assigns.length >= 2) {
    const vars = new Map(assigns.map((m) => [m[1].toLowerCase(), m[3]]));
    const expr = /\b([a-z]\w{0,11})\s*\+\s*([a-z]\w{0,11})(?:\s*\+\s*([a-z]\w{0,11}))?(?:\s*\+\s*([a-z]\w{0,11}))?/i.exec(t);
    if (expr) { const parts = expr.slice(1).filter(Boolean).map((v) => vars.get(v.toLowerCase())); if (parts.every((p) => p != null)) out.push(parts.join('')); }
    out.push(assigns.map((m) => m[3]).join(''));
  }
  const quoted = Array.from(t.matchAll(/(["'`“”‘’])([^"'`“”‘’\n]{1,80})\1/g)).map((m) => m[2]);
  if (quoted.length >= 3 && /\b(concat\w*|combine|join|put (?:them )?together|merge|append|glue)\b/i.test(t)) out.push(quoted.join(''), quoted.join(' '));
  return out;
}
/* The canonical view the English rules run on. */
export function canonical(s) {
  let t = stripInvisible(String(s ?? '')).normalize('NFKC').toLowerCase();
  t = foldHomoglyphs(t);
  t = t.replace(/[‘’‚‛′`´]/g, "'").replace(/[“”„‟″]/g, '"').replace(/[‐‑‒–—―]/g, '-');
  return t.replace(/[ \t\u00A0\u2000-\u200A\u3000]+/g, ' ');
}
/* Every letter only, for spacing and punctuation tricks ("i-g-n-o-r-e" or "ig.nore pre.vious"). */
export function compact(s) { return canonical(s).replace(/[^\p{L}]/gu, ''); }
/* All views of a text, labelled, each already canonicalised. Decoded views are marked obfuscated. */
export function views(s, o = {}) {
  const raw = String(s ?? ''); const out = [];
  const add = (layer, text, obf) => { if (text == null) return; const c = canonical(text); if (!c.trim()) return; if (out.some((v) => v.text === c)) return; out.push({ layer, text: c, obfuscated: !!obf }); };
  add('text', raw, false);
  const native = stripInvisible(raw).normalize('NFKC').toLowerCase(); if (!out.some((v) => v.text === native)) out.push({ layer: 'native-script', text: native, obfuscated: false });
  add('de-leet', deLeet(stripInvisible(raw).normalize('NFKC')), true);
  add('letter-spacing', collapseSpacedLetters(stripInvisible(raw).normalize('NFKC')), true);
  out.push({ layer: 'compact', text: compact(raw), obfuscated: true, compact: true });
  const tags = decodeTags(raw); if (tags.length >= 4) add('unicode-tags', tags, true);
  if (o.decode !== false) {
    for (const d of decodeSegments(raw)) { add(d.kind, d.text, true); add(d.kind + '+de-leet', deLeet(d.text), true); }
    add('rot13', rot13(raw), true);
    add('reversed', reverse(stripInvisible(raw)), true);
    for (const j of joinFragments(raw)) add('joined-fragments', j, true);
  }
  return out;
}
