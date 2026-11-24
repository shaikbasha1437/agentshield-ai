/* Storage: IndexedDB for app state (policies, runs, audit, approvals, settings), with a localStorage fallback
   when IndexedDB is blocked. API keys are kept only in memory unless you tick "remember", and are never part
   of state, exports, share links or the audit log. */
export const ls = { get(k, d) { try { const v = localStorage.getItem(k); return v == null ? d : JSON.parse(v); } catch (e) { return d; } }, set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); return true; } catch (e) { return false; } }, del(k) { try { localStorage.removeItem(k); } catch (e) { /* ignore */ } } };
let dbp = null;
function db() { if (dbp) return dbp; dbp = new Promise((res, rej) => { if (typeof indexedDB === 'undefined') { rej(new Error('IndexedDB unavailable')); return; } const r = indexedDB.open('agentshield', 1) /* database name kept from the project's earlier name so saved state survives the rename */; r.onupgradeneeded = () => r.result.createObjectStore('kv'); r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); }); return dbp; }
async function tx(mode, fn) { const d = await db(); return new Promise((res, rej) => { const t = d.transaction('kv', mode); const req = fn(t.objectStore('kv')); t.oncomplete = () => res(req && req.result); t.onerror = () => rej(t.error); t.onabort = () => rej(t.error || new Error('aborted')); }); }
const FALLBACK = 'as.state';
export async function load() { try { const v = await tx('readonly', (s) => s.get('state')); if (v) return v; } catch (e) { /* fall through */ } return ls.get(FALLBACK, null); }
let pending = null; let timer = null; export let where = 'memory';
export async function saveNow(state) { const copy = JSON.parse(JSON.stringify(state)); try { await tx('readwrite', (s) => s.put(copy, 'state')); ls.del(FALLBACK); where = 'idb'; } catch (e) { where = ls.set(FALLBACK, copy) ? 'ls' : 'memory'; } return where; }
export function save(state) { pending = state; clearTimeout(timer); timer = setTimeout(() => { const s = pending; pending = null; saveNow(s); }, 150); }
export async function flush() { if (pending) { clearTimeout(timer); const s = pending; pending = null; return saveNow(s); } return where; }
export async function clear() { clearTimeout(timer); pending = null; try { await tx('readwrite', (s) => s.delete('state')); } catch (e) { /* ignore */ } ls.del(FALLBACK); }
export async function getKey(k) { try { return await tx('readonly', (s) => s.get(k)); } catch (e) { return null; } }
export async function putKey(k, v) { try { await tx('readwrite', (s) => s.put(v, k)); return true; } catch (e) { return false; } }
export async function delKey(k) { try { await tx('readwrite', (s) => s.delete(k)); } catch (e) { /* ignore */ } }
if (typeof addEventListener !== 'undefined') addEventListener('pagehide', () => { flush(); });
