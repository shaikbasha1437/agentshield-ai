/* Hidden-text detection for untrusted HTML, Markdown and plain text. People see the rendered page; a model
   reads the source. Anything a person would not see (comments, CSS-hidden or white text, off-screen boxes,
   alt/title/aria text, invisible characters, Unicode tag smuggling, link-reference comments) is pulled out and
   reported, so the guard can strip or inspect it. A regex scanner, not a browser: deeply nested or script-built
   content can slip past, which is why indirect content is also checked for instructions as a whole. */
import { decodeEntities, decodeTags, countInvisible, stripInvisible } from './normalize.js';

export const HIDE_STYLE = [
  [/display\s*:\s*none/i, 'display:none'], [/visibility\s*:\s*hidden/i, 'visibility:hidden'], [/font-size\s*:\s*0(?:\.0+)?(?:px|pt|em|rem|%)?\s*(?:;|$|!)/i, 'font-size:0'],
  [/opacity\s*:\s*0(?:\.0\d*)?\s*(?:;|$|!)/i, 'opacity:0'], [/(?:left|top|right|text-indent|margin-left)\s*:\s*-\d{3,}/i, 'positioned off-screen'], [/(?:height|width|max-height)\s*:\s*0(?:px)?\s*;[^"']*overflow\s*:\s*hidden/i, 'zero-size box'],
  [/clip(?:-path)?\s*:\s*(?:rect\(\s*0|inset\(\s*50%|circle\(\s*0)/i, 'clipped away'], [/transform\s*:\s*scale\(\s*0\s*\)/i, 'scaled to zero']
];
export const WHITE = /(?:^|[;\s"'])color\s*:\s*(#f{3}\b|#f{6}\b|white\b|rgba?\(\s*255\s*,\s*255\s*,\s*255|hsl\(\s*\d+\s*,\s*\d+%\s*,\s*100%)/i;
export const TRANSPARENT = /(?:^|[;\s"'])color\s*:\s*(transparent|rgba\([^)]*,\s*0(?:\.0+)?\s*\))/i;
function bgOf(style) { const m = /background(?:-color)?\s*:\s*([^;"']+)/i.exec(style || ''); return m ? m[1].trim().toLowerCase() : null; }
function colorOf(style) { const m = /(?:^|[;\s"'])color\s*:\s*([^;"']+)/i.exec(style || ''); return m ? m[1].trim().toLowerCase() : null; }
export function htmlToText(html) {
  return decodeEntities(String(html).replace(/<(script|style|noscript|template)\b[\s\S]*?<\/\1>/gi, ' ').replace(/<!--[\s\S]*?-->/g, ' ').replace(/<br\s*\/?>/gi, '\n').replace(/<\/(p|div|li|h\d|tr|section|article)>/gi, '\n').replace(/<[^>]+>/g, ' ')).replace(/[ \t]+/g, ' ').replace(/\n\s*\n+/g, '\n').trim();
}
export function looksLikeHtml(s) { return /<\/?(html|body|div|span|p|a|img|section|article|table|li|ul|h\d|meta|br|font|style|script)\b[^>]*>/i.test(String(s)); }
/** Returns { findings: [{ kind, text, detail }], visible, hidden }. */
export function scanHidden(content, o = {}) {
  let s = String(content ?? ''); const findings = []; const add = (kind, text, detail) => { const t = String(text || '').replace(/\s+/g, ' ').trim(); if (t) findings.push({ kind, text: t.slice(0, 2000), detail: detail || '' }); };
  const format = o.format || (looksLikeHtml(s) ? 'html' : /!\[[^\]]*\]\(|\[[^\]]+\]\(|^#{1,6}\s/m.test(s) ? 'markdown' : 'text');
  // invisible characters first (all formats)
  const tags = decodeTags(s.replace(/\u{1F3F4}[\u{E0061}-\u{E007A}]{2,7}\u{E007F}/gu, '')); if (tags.trim().length >= 4) add('unicode-tags', tags, 'Unicode tag characters (invisible) spell out text');
  const inv = countInvisible(s); if (inv.zeroWidth >= 3) add('zero-width', inv.zeroWidth + ' zero-width characters', 'invisible characters that can split or hide words');
  if (inv.bidi) add('bidi', inv.bidi + ' bidirectional control characters', 'can make text display in a different order than it is read');
  let visible = s;
  if (format === 'html') {
    for (const m of s.matchAll(/<!--([\s\S]*?)-->/g)) add('html-comment', m[1], 'HTML comment');
    for (const m of s.matchAll(/<(script|noscript|template)\b[^>]*>([\s\S]*?)<\/\1>/gi)) { const txt = m[2].replace(/<[^>]+>/g, ' '); if (/[a-z]{3,}\s+[a-z]{3,}\s+[a-z]{3,}/i.test(txt) && !/^\s*[{[(]/.test(txt) && !/function|=>|var |const |let |\(\)/.test(txt)) add(m[1].toLowerCase(), txt, '<' + m[1].toLowerCase() + '> text that is not displayed'); }
    for (const m of s.matchAll(/<meta\b[^>]*\bcontent\s*=\s*("([^"]*)"|'([^']*)')[^>]*>/gi)) { const v = m[2] ?? m[3]; if (v && v.split(/\s+/).length >= 6) add('meta', decodeEntities(v), '<meta> content'); }
    for (const el of elements(s)) { const why = hiddenWhy(el.attrs); if (why) { const inner = htmlToText(el.inner); if (inner) add('css-hidden', inner, why); } }
    for (const m of s.matchAll(/<font\b[^>]*color\s*=\s*["']?(#?f{3}\b|#?f{6}\b|white)[^>]*>([\s\S]*?)<\/font>/gi)) add('css-hidden', htmlToText(m[2]), 'white <font> text');
    for (const m of s.matchAll(/\b(alt|title|aria-label|data-[\w-]+|placeholder)\s*=\s*("([^"]{20,})"|'([^']{20,})')/gi)) { const v = decodeEntities(m[3] ?? m[4]); if (v.split(/\s+/).length >= 5) add('attribute', v, m[1].toLowerCase() + ' attribute text'); }
    for (const m of s.matchAll(/<img\b[^>]*\bsrc\s*=\s*["']?([^"'\s>]+)/gi)) { const u = m[1]; if (/[?&][^=]+=[^&]{12,}/.test(u)) add('image-url-data', u, 'image URL carrying query data'); }
    visible = htmlToText(stripHiddenHtml(s));
  } else {
    for (const m of s.matchAll(/<!--([\s\S]*?)-->/g)) add('html-comment', m[1], 'HTML comment in ' + format);
    for (const m of s.matchAll(/^\s*\[(?:\/\/|comment|_)\]:\s*(?:#|<>)?\s*[("']([^)"']+)[)"']/gim)) add('markdown-comment', m[1], 'Markdown link-reference comment (not rendered)');
    for (const m of s.matchAll(/!\[([^\]]*)\]\(\s*<?([^)\s>]+)>?(?:\s+["']([^"']*)["'])?\s*\)/g)) {
      if (m[1] && m[1].split(/\s+/).length >= 5) add('alt-text', m[1], 'image alt text');
      if (m[3] && m[3].split(/\s+/).length >= 5) add('attribute', m[3], 'image title text');
      if (/[?&][^=]+=[^&)]{12,}/.test(m[2]) || /\{[^}]*\}/.test(m[2])) add('image-url-data', m[2], 'image URL carrying query data');
    }
    for (const m of s.matchAll(/<(span|div|p|font)\b([^>]*)>([\s\S]*?)<\/\1>/gi)) { const st = m[2]; if (HIDE_STYLE.some(([re]) => re.test(st)) || WHITE.test(st)) add('css-hidden', htmlToText(m[3]), 'inline HTML hidden by style'); }
    visible = s.replace(/<!--[\s\S]*?-->/g, '').replace(/^\s*\[(?:\/\/|comment|_)\]:.*$/gim, '');
  }
  visible = stripInvisible(visible);
  const hidden = findings.filter((f) => !['zero-width', 'bidi'].includes(f.kind)).map((f) => f.text).join('\n');
  return { format, findings, visible, hidden };
}
const VOID = new Set(['br', 'img', 'hr', 'input', 'meta', 'link', 'source', 'area', 'base', 'col', 'embed', 'param', 'track', 'wbr']);
/* Every element with its inner HTML, matching nested tags of the same name by depth. */
export function elements(s) {
  const out = []; const re = /<(\/?)([a-zA-Z][\w-]*)\b([^>]*?)(\/?)>/g; const stack = []; let m;
  while ((m = re.exec(s))) {
    const close = m[1] === '/'; const tag = m[2].toLowerCase();
    if (VOID.has(tag) || m[4] === '/') continue;
    if (!close) stack.push({ tag, attrs: m[3], start: m.index, innerStart: re.lastIndex });
    else { for (let i = stack.length - 1; i >= 0; i--) if (stack[i].tag === tag) { const o = stack[i]; stack.length = i; out.push({ tag, attrs: o.attrs, inner: s.slice(o.innerStart, m.index), start: o.start, end: re.lastIndex }); break; } }
    if (out.length > 20000) break;
  }
  return out;
}
function styleOf(attrs) { const m = /\bstyle\s*=\s*(?:"([^"]*)"|'([^']*)')/i.exec(attrs || ''); return m ? (m[1] ?? m[2]) : ''; }
export function hiddenWhy(attrs) {
  const style = styleOf(attrs);
  for (const [re, label] of HIDE_STYLE) if (re.test(style)) return label;
  if (/(?:^|\s)hidden(?:\s|$|=)/i.test(attrs.replace(/\b[\w-]+\s*=\s*("[^"]*"|'[^']*')/g, ' ')) && !/hidden\s*=\s*["']?false/i.test(attrs)) return 'hidden attribute';
  if (/aria-hidden\s*=\s*["']?true/i.test(attrs)) return 'aria-hidden';
  if (/\bclass\s*=\s*["'][^"']*\b(sr-only|visually-hidden|screen-reader-only|d-none|invisible|offscreen)\b/i.test(attrs)) return 'hidden by class';
  const c = colorOf(style); const bg = bgOf(style);
  if (c && bg && c.replace(/\s/g, '') === bg.replace(/\s/g, '')) return 'text colour matches background';
  if (WHITE.test(style) && (!bg || /^(#f{3}|#f{6}|white)\b/.test(bg))) return 'white text';
  if (TRANSPARENT.test(style)) return 'transparent text';
  return null;
}
function stripHiddenHtml(s) {
  let out = s.replace(/<!--[\s\S]*?-->/g, '');
  const ranges = elements(out).filter((el) => hiddenWhy(el.attrs)).map((el) => [el.start, el.end]).sort((a, b) => a[0] - b[0]);
  let res = ''; let pos = 0; for (const [a, b] of ranges) { if (a < pos) continue; res += out.slice(pos, a) + ' '; pos = b; } res += out.slice(pos);
  return res.replace(/<font\b[^>]*color\s*=\s*["']?(#?f{3}\b|#?f{6}\b|white)[^>]*>[\s\S]*?<\/font>/gi, ' ');
}
