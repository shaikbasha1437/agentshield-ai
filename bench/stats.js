/* Statistics for the benchmark: Wilson intervals, percentiles (NumPy's linear method) and McNemar's exact
   test for comparing two policies on the same cases. Ported from EvalBoard; cross-checked against SciPy. */
export const Z95 = 1.959963984540054;
export function wilson(k, n, z = Z95) {
  if (!n) return { p: NaN, lo: NaN, hi: NaN };
  const p = k / n; const d = 1 + z * z / n; const c = (p + z * z / (2 * n)) / d; const h = z * Math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d;
  return { p, lo: Math.max(0, c - h), hi: Math.min(1, c + h) };
}
export function percentile(arr, q) {
  const a = arr.filter((x) => x != null && isFinite(x)).slice().sort((x, y) => x - y);
  if (!a.length) return NaN; const pos = (q / 100) * (a.length - 1); const lo = Math.floor(pos); const hi = Math.ceil(pos);
  return a[lo] + (a[hi] - a[lo]) * (pos - lo);
}
export function mean(a) { const v = a.filter((x) => isFinite(x)); return v.length ? v.reduce((s, x) => s + x, 0) / v.length : NaN; }
const LG = [676.5203681218851, -1259.1392167224028, 771.32342877765313, -176.61502916214059, 12.507343278686905, -0.13857109526572012, 9.9843695780195716e-6, 1.5056327351493116e-7];
export function lgamma(x) { if (x < 0.5) return Math.log(Math.PI / Math.abs(Math.sin(Math.PI * x))) - lgamma(1 - x); x -= 1; let a = 0.99999999999980993; const t = x + 7.5; for (let i = 0; i < 8; i++) a += LG[i] / (x + i + 1); return 0.5 * Math.log(2 * Math.PI) + (x + 0.5) * Math.log(t) - t + Math.log(a); }
export function binomCdf(k, n, p) { let s = 0; for (let i = 0; i <= k; i++) s += Math.exp(lgamma(n + 1) - lgamma(i + 1) - lgamma(n - i + 1) + i * Math.log(p) + (n - i) * Math.log(1 - p)); return Math.min(1, s); }
/** b = cases only policy A stopped, c = cases only policy B stopped. Two-sided exact p. */
export function mcnemar(b, c) { const n = b + c; if (!n) return { b, c, n, p: 1 }; return { b, c, n, p: Math.min(1, 2 * binomCdf(Math.min(b, c), n, 0.5)) }; }
