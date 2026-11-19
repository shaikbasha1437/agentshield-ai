/* Shared UI helpers: escaping, toasts with undo, accessible modals that close via X, Cancel, Esc, a backdrop
   click and the browser Back button (with a discard prompt for unsaved edits), downloads and copy. */
export const $ = (s, r) => (r || document).querySelector(s);
export const $$ = (s, r) => Array.from((r || document).querySelectorAll(s));
export const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
export const clone = (x) => JSON.parse(JSON.stringify(x));
export const uid = (p) => p + '-' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
export const when = (iso) => { if (!iso) return ''; const d = new Date(iso); return d.toLocaleString('en-US', { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' }); };
export const fileSlug = (s) => String(s || 'export').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
export const pct = (p, d = 1) => (p == null || !isFinite(p) ? 'n/a' : (p * 100).toFixed(d) + '%');
let toastTimer = null;
export function toast(msg, undo) {
  const t = $('#toast');
  t.innerHTML = '<span>' + esc(msg) + '</span>' + (undo ? '<button type="button" id="toast-undo">Undo</button>' : '');
  t.classList.add('show');
  if (undo) $('#toast-undo').onclick = () => { t.classList.remove('show'); undo(); };
  clearTimeout(toastTimer); toastTimer = setTimeout(() => t.classList.remove('show'), undo ? 8000 : 3800);
}
let modal = null; let lastFocus = null;
export const modalOpen = () => !!modal;
export function openModal(title, html, o) {
  const op = o || {};
  if (modal) removeModal('replaced'); else { lastFocus = document.activeElement; window.history.pushState({ asModal: true }, ''); }
  $('#modal-host').innerHTML = '<div class="backdrop"><section class="modal ' + (op.wide ? 'wide' : '') + '" role="dialog" aria-modal="true" aria-labelledby="modal-title"' + (op.name ? ' data-modal="' + esc(op.name) + '"' : '') + '><div class="modal-header"><h2 id="modal-title">' + esc(title) + '</h2><button type="button" data-close="x" aria-label="Close">×</button></div><div class="modal-body">' + html + '</div><div class="modal-footer">' + (op.extraFooter || '') + '<button type="button" data-close="cancel">' + esc(op.cancelLabel || (op.save ? 'Cancel' : 'Close')) + '</button>' + (op.save ? '<button type="button" id="modal-save" class="primary">' + esc(op.saveLabel || 'Save') + '</button>' : '') + '</div></section></div>';
  modal = { dirty: false, watch: !!op.dirty, onClose: op.onClose || null, name: op.name || '' };
  document.body.style.overflow = 'hidden';
  $('.backdrop').addEventListener('mousedown', (e) => { if (e.target.classList.contains('backdrop')) closeModal(); });
  $$('[data-close]').forEach((b) => (b.onclick = () => closeModal()));
  $('.modal-body').addEventListener('input', (e) => { if (modal && modal.watch && !(e.target && e.target.dataset && e.target.dataset.nodirty != null)) modal.dirty = true; });
  if (op.save) $('#modal-save').onclick = () => op.save();
  if (op.onmount) op.onmount();
  setTimeout(() => { if (!modal) return; const first = $('.modal-body input:not([type=checkbox]):not([type=radio]):not([type=hidden]):not([type=file]):not([readonly]),.modal-body textarea:not([readonly]),.modal-body select'); const el = op.focusFirst && first ? first : $('.modal [data-close=x]'); if (el) el.focus(); }, 0);
}
function removeModal(reason) { const m = modal; modal = null; $('#modal-host').innerHTML = ''; document.body.style.overflow = ''; if (reason !== 'replaced' && lastFocus && lastFocus.focus && document.contains(lastFocus)) lastFocus.focus({ preventScroll: true }); if (m && m.onClose) m.onClose(reason || 'cancel'); }
/** Close the open modal. force skips the discard prompt (after a successful save). */
export function closeModal(force, reason) { if (!modal || modal.closing) return; if (!force && modal.dirty && !confirm('Discard unsaved changes?')) return; modal.dirty = false; modal.closing = true; modal.reason = reason; const m = modal; window.history.back(); setTimeout(() => { if (modal === m) removeModal(m.reason); }, 800); }
export function setDirty(v) { if (modal) modal.dirty = !!v; }
addEventListener('popstate', () => { if (!modal) return; if (!modal.closing && modal.dirty && !confirm('Discard unsaved changes?')) { window.history.pushState({ asModal: true }, ''); return; } removeModal(modal.reason); });
addEventListener('keydown', (e) => {
  if (!modal) return;
  if (e.key === 'Escape') { e.preventDefault(); closeModal(); return; }
  if (e.key === 'Tab') { const els = $$('.modal button,.modal input,.modal select,.modal textarea,.modal a[href],.modal [tabindex="0"]').filter((x) => !x.disabled && x.offsetParent !== null); if (!els.length) return; const f = els[0]; const l = els[els.length - 1]; if (!document.activeElement || !document.activeElement.closest('.modal')) { (e.shiftKey ? l : f).focus(); e.preventDefault(); return; } if (e.shiftKey && document.activeElement === f) { l.focus(); e.preventDefault(); } else if (!e.shiftKey && document.activeElement === l) { f.focus(); e.preventDefault(); } }
});
export function download(name, data, type) { const blob = new Blob([data], { type: type || 'text/plain' }); const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = name; document.body.appendChild(a); a.click(); setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1500); }
export async function copy(text, msg) { try { await navigator.clipboard.writeText(text); toast(msg || 'Copied.'); return true; } catch (e) { toast('Copy failed; select the text and copy it yourself.'); return false; } }
/** Render a line diff ([{op,text}]) as HTML. */
export function diffHtml(lines) { return '<div class="ldiff">' + lines.map((l) => '<div class="dl ' + (l.op === '+' ? 'add' : l.op === '-' ? 'del' : 'same') + '"><span class="dm">' + (l.op === ' ' ? '\u00a0' : l.op) + '</span>' + esc(l.text) + '</div>').join('') + '</div>'; }
/** Remove every known secret from a string before it leaves the app (exports, share links, copies). */
export function scrub(text, secrets) { let s = String(text ?? ''); for (const k of (secrets || []).filter((x) => x && x.length >= 6)) s = s.split(k).join('[key removed]'); return s; }
