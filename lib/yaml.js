/* A small YAML subset parser and serializer for policy files, with no dependencies. Supports block maps and
   lists, flow [lists] and {maps}, quoted and plain scalars, comments and | / > block strings. Anchors, aliases,
   tags and multi-document files are rejected with a line-numbered error rather than guessed at.
   parseYaml returns { value, errors, lines } where lines maps a dotted path (tools.rules.send_email) to its line. */
export class YamlError extends Error { constructor(msg, line) { super(line ? 'Line ' + line + ': ' + msg : msg); this.line = line; this.reason = msg; } }

function stripComment(s) {
  let q = null;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (q) { if (c === q) { if (q === "'" && s[i + 1] === "'") { i++; continue; } q = null; } else if (c === '\\' && q === '"') i++; continue; }
    if (c === '"' || c === "'") { if (i === 0 || /[\s:[{,\-]/.test(s[i - 1])) q = c; continue; }
    if (c === '#' && (i === 0 || /\s/.test(s[i - 1]))) return s.slice(0, i);
  }
  return s;
}
function splitKey(s) {
  // returns [key, rest] if s is "key: rest" (colon followed by space/end, outside quotes), else null
  let i = 0; let key;
  if (s[0] === '"' || s[0] === "'") {
    const q = s[0]; let j = 1; for (; j < s.length; j++) { if (s[j] === '\\' && q === '"') { j++; continue; } if (s[j] === q) { if (q === "'" && s[j + 1] === "'") { j++; continue; } break; } }
    if (j >= s.length) return null; key = unquote(s.slice(0, j + 1)); i = j + 1; while (s[i] === ' ') i++;
    if (s[i] !== ':' || (i + 1 < s.length && s[i + 1] !== ' ')) return null; return [key, s.slice(i + 1).trim()];
  }
  for (; i < s.length; i++) { if (s[i] === ':' && (i + 1 === s.length || s[i + 1] === ' ' || s[i + 1] === '\t')) { key = s.slice(0, i).trim(); if (!key || /^[[{]/.test(key)) return null; return [key, s.slice(i + 1).trim()]; } }
  return null;
}
function unquote(s) {
  if (s[0] === '"') { try { return JSON.parse(s.replace(/\t/g, '\\t')); } catch (e) { throw new YamlError('Bad double-quoted string ' + s); } }
  return s.slice(1, -1).replace(/''/g, "'");
}
function scalar(s, line) {
  const t = s.trim();
  if (t === '' || t === '~' || t === 'null' || t === 'Null' || t === 'NULL') return null;
  if (/^(true|True|TRUE)$/.test(t)) return true; if (/^(false|False|FALSE)$/.test(t)) return false;
  if (/^[-+]?(\d[\d_]*)(\.\d+)?([eE][-+]?\d+)?$/.test(t)) return Number(t.replace(/_/g, ''));
  if (/^0x[0-9a-f]+$/i.test(t)) return parseInt(t, 16);
  if (t[0] === '"' || t[0] === "'") { if (t[t.length - 1] !== t[0] || t.length < 2) throw new YamlError('Unclosed quoted string', line); return unquote(t); }
  if (t[0] === '&' || t[0] === '*') throw new YamlError('Anchors and aliases are not supported', line);
  if (t[0] === '!') throw new YamlError('Tags are not supported', line);
  if (t[0] === '[' || t[0] === '{') return flow(t, line);
  if (t[0] === '@' || t[0] === '`') throw new YamlError('A plain value cannot start with ' + t[0] + '; quote it', line);
  return t;
}
function flow(src, line) {
  let i = 0;
  const ws = () => { while (i < src.length && /\s/.test(src[i])) i++; };
  function str() { const q = src[i]; let j = i + 1; for (; j < src.length; j++) { if (src[j] === '\\' && q === '"') { j++; continue; } if (src[j] === q) { if (q === "'" && src[j + 1] === "'") { j++; continue; } break; } } if (j >= src.length) throw new YamlError('Unclosed quoted string in flow value', line); const v = unquote(src.slice(i, j + 1)); i = j + 1; return v; }
  function plain(stops) { let j = i; while (j < src.length && !stops.includes(src[j])) { if (src[j] === ':' && (src[j + 1] === ' ' || src[j + 1] === undefined) && stops.includes(':')) break; j++; } const t = src.slice(i, j); i = j; return t; }
  function val(stops) { ws(); const c = src[i]; if (c === '[') return list(); if (c === '{') return map(); if (c === '"' || c === "'") return str(); return scalar(plain(stops), line); }
  function list() { i++; const out = []; ws(); if (src[i] === ']') { i++; return out; } for (;;) { out.push(val([',', ']'])); ws(); if (src[i] === ',') { i++; ws(); if (src[i] === ']') { i++; return out; } continue; } if (src[i] === ']') { i++; return out; } throw new YamlError('Expected , or ] in a flow list', line); } }
  function map() { i++; const out = {}; ws(); if (src[i] === '}') { i++; return out; } for (;;) { ws(); const k = (src[i] === '"' || src[i] === "'") ? str() : plain([':', ',', '}']).trim(); ws(); if (src[i] !== ':') throw new YamlError('Expected key: value in a flow map', line); i++; out[k] = val([',', '}']); ws(); if (src[i] === ',') { i++; ws(); if (src[i] === '}') { i++; return out; } continue; } if (src[i] === '}') { i++; return out; } throw new YamlError('Expected , or } in a flow map', line); } }
  const v = val([]); ws(); if (i < src.length) throw new YamlError('Unexpected text after a flow value: ' + src.slice(i, i + 20), line); return v;
}

export function parseYaml(text) {
  const raw = String(text ?? '').replace(/\r\n?/g, '\n').split('\n');
  const L = []; const errors = []; const lines = {};
  for (let n = 0; n < raw.length; n++) {
    const r = raw[n]; if (/^\t/.test(r)) { errors.push(new YamlError('Tabs are not allowed for indentation', n + 1)); continue; }
    if (/^(---|\.\.\.)\s*$/.test(r)) { if (L.length) errors.push(new YamlError('Only one YAML document is supported', n + 1)); continue; }
    const c = stripComment(r).replace(/\s+$/, ''); if (!c.trim()) { L.push({ blank: true, raw: r, line: n + 1 }); continue; }
    L.push({ indent: c.length - c.trimStart().length, text: c.trim(), raw: r, line: n + 1 });
  }
  let i = 0;
  const next = () => { while (i < L.length && L[i].blank) i++; return L[i]; };
  function block(indent, path) {
    const l = next(); if (!l || l.indent < indent) return null;
    if (l.text === '-' || l.text.startsWith('- ')) return seq(l.indent, path);
    if (splitKey(l.text)) return mapping(l.indent, path);
    i++; const v = scalar(l.text, l.line); const n2 = next(); if (n2 && n2.indent > l.indent) throw new YamlError('Unexpected indentation', n2.line); return v;
  }
  function blockScalar(style, parentIndent) {
    const out = []; let base = null; const keep = /\+/.test(style); const strip = /-/.test(style);
    while (i < L.length) { const l = L[i]; if (l.blank) { out.push(''); i++; continue; } if (l.indent <= parentIndent) break; if (base == null) base = l.indent; out.push(l.raw.slice(base)); i++; }
    while (!keep && out.length && out[out.length - 1] === '') out.pop();
    let s = style[0] === '>' ? out.join('\n').replace(/([^\n])\n(?=[^\n])/g, '$1 ') : out.join('\n');
    if (!strip && s) s += '\n'; return s;
  }
  function mapping(indent, path) {
    const out = {};
    for (;;) {
      const l = next(); if (!l || l.indent < indent) break;
      if (l.indent > indent) throw new YamlError('Unexpected indentation', l.line);
      const kv = splitKey(l.text); if (!kv) { if (l.text.startsWith('- ')) throw new YamlError('A list item where a key was expected (check indentation)', l.line); throw new YamlError('Expected "key: value"', l.line); }
      const [k, rest] = kv; const p = path ? path + '.' + k : k; lines[p] = l.line;
      if (Object.prototype.hasOwnProperty.call(out, k)) errors.push(new YamlError('Duplicate key "' + k + '"', l.line));
      i++;
      if (rest === '') { const n2 = next(); if (n2 && (n2.indent > indent || (n2.indent === indent && (n2.text === '-' || n2.text.startsWith('- '))))) out[k] = block(n2.indent, p); else out[k] = null; }
      else if (/^[|>][-+]?$/.test(rest)) out[k] = blockScalar(rest, indent);
      else { out[k] = scalar(rest, l.line); }
    }
    return out;
  }
  function seq(indent, path) {
    const out = [];
    for (;;) {
      const l = next(); if (!l || l.indent < indent) break;
      if (l.indent > indent) throw new YamlError('Unexpected indentation', l.line);
      if (!(l.text === '-' || l.text.startsWith('- '))) break;
      const p = path + '[' + out.length + ']'; lines[p] = l.line;
      const rest = l.text === '-' ? '' : l.text.slice(2).trim();
      if (rest === '') { i++; const n2 = next(); out.push(n2 && n2.indent > indent ? block(n2.indent, p) : null); continue; }
      if (rest.startsWith('- ') || splitKey(rest)) { const off = l.text.length - l.text.slice(1).trimStart().length; L[i] = { indent: indent + off, text: rest, raw: l.raw, line: l.line }; out.push(block(indent + off, p)); continue; }
      i++;
      if (/^[|>][-+]?$/.test(rest)) { out.push(blockScalar(rest, indent)); continue; }
      out.push(scalar(rest, l.line));
    }
    return out;
  }
  let value = null;
  try {
    const first = next();
    if (first && (first.text[0] === '{' || first.text[0] === '[') && !splitKey(first.text)) {
      const joined = L.filter((x) => !x.blank).map((x) => x.text).join(' ');
      try { value = JSON.parse(joined); } catch (e) { value = flow(joined, first.line); }
      i = L.length;
    } else value = block(0, '');
    const rest = next(); if (rest) throw new YamlError('Unexpected content (check indentation)', rest.line);
  } catch (e) { if (e instanceof YamlError) errors.push(e); else errors.push(new YamlError(e.message)); value = errors.length ? value : null; }
  return { value, errors: errors.map((e) => ({ line: e.line || null, message: e.reason || e.message })), lines };
}

const RESERVED = /^(true|false|null|yes|no|on|off|~|-?\d[\d_]*(\.\d+)?([eE][-+]?\d+)?|0x[0-9a-f]+)$/i;
function q(s) {
  if (s === '' || RESERVED.test(s) || /^[\s\-?:,[\]{}#&*!|>'"%@`]|[:#]\s|:$|\s$|\n|\t/.test(s) || /^- /.test(s)) return JSON.stringify(s);
  return s;
}
function sc(v) { if (v === null || v === undefined) return 'null'; if (typeof v === 'string') return q(v); if (typeof v === 'number' || typeof v === 'boolean') return String(v); return JSON.stringify(v); }
const isPlainList = (a) => a.every((x) => x === null || ['string', 'number', 'boolean'].includes(typeof x));
export function toYaml(v, indent = 0) {
  const pad = ' '.repeat(indent);
  if (Array.isArray(v)) {
    if (!v.length) return '[]';
    return v.map((x) => {
      if (x && typeof x === 'object' && !Array.isArray(x) && Object.keys(x).length) { const inner = toYaml(x, indent + 2); return pad + '- ' + inner.slice(indent + 2); }
      if (Array.isArray(x) && x.length) return pad + '- ' + (isPlainList(x) ? '[' + x.map(sc).join(', ') + ']' : JSON.stringify(x));
      return pad + '- ' + (x && typeof x === 'object' ? (Array.isArray(x) ? '[]' : '{}') : sc(x));
    }).join('\n');
  }
  if (v && typeof v === 'object') {
    const ks = Object.keys(v); if (!ks.length) return pad + '{}';
    return ks.map((k) => {
      const x = v[k]; const kk = q(k);
      if (Array.isArray(x)) { if (!x.length) return pad + kk + ': []'; if (isPlainList(x) && JSON.stringify(x).length < 70) return pad + kk + ': [' + x.map(sc).join(', ') + ']'; return pad + kk + ':\n' + toYaml(x, indent + 2); }
      if (x && typeof x === 'object') { if (!Object.keys(x).length) return pad + kk + ': {}'; return pad + kk + ':\n' + toYaml(x, indent + 2); }
      if (typeof x === 'string' && x.includes('\n')) return pad + kk + ': |' + (x.endsWith('\n') ? '' : '-') + '\n' + x.replace(/\n$/, '').split('\n').map((ln) => (ln ? pad + '  ' + ln : '')).join('\n');
      return pad + kk + ': ' + sc(x);
    }).join('\n');
  }
  return pad + sc(v);
}
