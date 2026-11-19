/* Line diff (longest common subsequence) for the approval queue: shows what a file write or edit would change. */
export function lineDiff(before, after) {
  const a = String(before ?? '').split('\n'); const b = String(after ?? '').split('\n');
  if (before == null || before === '') return b.map((t) => ({ op: '+', text: t }));
  const n = a.length; const m = b.length;
  if (n * m > 4e6) return a.map((t) => ({ op: '-', text: t })).concat(b.map((t) => ({ op: '+', text: t })));
  const L = Array.from({ length: n + 1 }, () => new Uint32Array(m + 1));
  for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) L[i][j] = a[i] === b[j] ? L[i + 1][j + 1] + 1 : Math.max(L[i + 1][j], L[i][j + 1]);
  const out = []; let i = 0; let j = 0;
  while (i < n && j < m) { if (a[i] === b[j]) { out.push({ op: ' ', text: a[i] }); i++; j++; } else if (L[i + 1][j] >= L[i][j + 1]) out.push({ op: '-', text: a[i++] }); else out.push({ op: '+', text: b[j++] }); }
  while (i < n) out.push({ op: '-', text: a[i++] }); while (j < m) out.push({ op: '+', text: b[j++] });
  return out;
}
export function diffStats(d) { return { added: d.filter((x) => x.op === '+').length, removed: d.filter((x) => x.op === '-').length }; }
/* Field-level diff between two plain objects (for argument changes, e.g. an edited approval). */
export function fieldDiff(a, b) {
  const keys = Array.from(new Set(Object.keys(a || {}).concat(Object.keys(b || {}))));
  return keys.map((k) => ({ key: k, before: a ? a[k] : undefined, after: b ? b[k] : undefined, changed: JSON.stringify(a ? a[k] : undefined) !== JSON.stringify(b ? b[k] : undefined) }));
}
