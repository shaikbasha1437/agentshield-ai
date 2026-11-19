/* Tool/action firewall. Every tool call is checked against the policy before it runs: allow, deny or
   require a person's approval, with every reason listed. Checks: kill switch, per-tool action, path and domain
   allowlists, read-only SQL, amount limits and budgets, recipient allowlists, command allowlists, dangerous
   commands, argument deny-patterns, rate limits, taint from untrusted content, and sensitive actions taken
   while flagged content is in context. */
import { dangerousCommand, sqlReadOnly, shellSegments, COMMAND_ARG_KEYS } from './dangerous.js';
import { matchAny, parseUrl, hostAllowed } from './output.js';
import { SENSITIVE_KINDS } from './policy.js';

const RANK = { allow: 0, 'require-approval': 1, deny: 2 };
const worst = (a, b) => (RANK[b] > RANK[a] ? b : a);
const PATH_KEYS = ['path', 'file', 'filename', 'filepath', 'file_path', 'dir', 'directory', 'folder', 'target', 'src', 'source', 'dest', 'destination', 'from', 'output'];
const URL_KEYS = ['url', 'uri', 'href', 'link', 'endpoint', 'webhook', 'callback', 'site', 'page'];
const RCPT_KEYS = ['to', 'cc', 'bcc', 'recipient', 'recipients', 'email', 'emails', 'address', 'reply_to', 'replyto', 'forward_to'];
const AMOUNT_KEYS = ['amount', 'value', 'total', 'sum', 'price', 'usd', 'amount_usd', 'quantity_usd'];
/* Guess a tool's kind from its name when the policy does not say. */
export function guessKind(name) {
  const n = String(name).toLowerCase();
  if (/draft/.test(n) && /mail|email|message/.test(n)) return 'email-draft';
  if (/send.*(mail|email)|(mail|email).*send|^email$|forward/.test(n)) return 'email';
  if (/refund|charge|pay|transfer|wire|invoice_pay|payout|purchase/.test(n)) return 'payment';
  if (/shell|exec|terminal|bash|command|run_cmd|^sh$/.test(n)) return 'shell';
  if (/sql|query|database|db_/.test(n)) return 'sql';
  if (/delete_file|remove_file|unlink|rm_/.test(n)) return 'file-delete';
  if (/write|save|create_file|edit_file|append/.test(n)) return 'file-write';
  if (/read|open_file|list_files|cat|get_file|ls/.test(n)) return 'file-read';
  if (/fetch|http|browse|web|url|navigate|scrape/.test(n)) return 'web';
  if (/deploy|kubectl|scale|rollout|terraform/.test(n)) return 'deploy';
  if (/git|merge|push|commit/.test(n)) return 'git';
  if (/slack|post_message|send_message|sms|tweet/.test(n)) return 'message';
  if (/search|lookup|kb_/.test(n)) return 'search';
  return 'other';
}
export function normalizePath(p, cwd = '/workspace') {
  let s = String(p ?? '').replace(/\\/g, '/');
  if (s.startsWith('~')) s = '/home/user' + s.slice(1);
  if (!s.startsWith('/')) s = cwd.replace(/\/$/, '') + '/' + s;
  const out = []; for (const part of s.split('/')) { if (!part || part === '.') continue; if (part === '..') out.pop(); else out.push(part); }
  return '/' + out.join('/');
}
function pathMatch(p, globs) {
  return (globs || []).some((g) => { const re = new RegExp('^' + String(g).replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*\*\/?/g, '\u0000').replace(/\*/g, '\u0001').replace(/\?/g, '\u0002').replace(/\u0000/g, '(?:.*/)?.*').replace(/\u0001/g, '[^/]*').replace(/\u0002/g, '[^/]') + '$'); return re.test(p) || re.test(p + '/'); });
}
function walkStrings(args, fn, path = '') { if (args == null) return; if (typeof args === 'string' || typeof args === 'number') fn(String(args), path); else if (Array.isArray(args)) args.forEach((x, i) => walkStrings(x, fn, path + '[' + i + ']')); else if (typeof args === 'object') for (const [k, v] of Object.entries(args)) walkStrings(v, fn, path ? path + '.' + k : k); }
const keyOf = (path) => path.replace(/\[\d+\]/g, '').split('.').pop().toLowerCase();
export function parseAmount(v) { if (typeof v === 'number') return v; const m = /-?\d[\d,]*(?:\.\d+)?/.exec(String(v ?? '')); return m ? Number(m[0].replace(/,/g, '')) : NaN; }
export function emailsIn(v) { return (String(v ?? '').match(/[\w.%+-]+@[\w-]+(?:\.[\w-]+)+/g) || []).map((x) => x.toLowerCase()); }
export function createFirewallState() { return { calls: {}, spend: {}, all: [] }; }
/** Decide on one tool call.
 *  call = { tool, args }. ctx = { taint?: TaintTracker, state?: firewall state, now?: ms, cwd?: string }.
 *  Returns { tool, kind, action, reasons: [{ code, severity, detail, arg? }], risk, mode, wouldBe? }. */
export function checkToolCall(policy, call, ctx = {}) {
  const now = ctx.now ?? Date.now(); const st = ctx.state || createFirewallState();
  const tool = String(call && call.tool || ''); const args = (call && call.args) || {};
  const rules = (policy.tools && policy.tools.rules) || {}; const rule = rules[tool] || null;
  const kind = (rule && rule.kind) || guessKind(tool);
  const reasons = []; let action = 'allow'; let amount = NaN;
  const add = (severity, code, detail, arg) => { reasons.push({ code, severity, detail, arg }); action = worst(action, severity); };
  if (policy.killSwitch) { add('deny', 'kill-switch', 'The kill switch is on, so no tool may run.'); return finish(); }
  if (!tool) { add('deny', 'no-tool', 'The call names no tool.'); return finish(); }
  if (!rule) { const d = (policy.tools && policy.tools.default) || 'require-approval'; if (d !== 'allow') add(d, 'unlisted-tool', '"' + tool + '" is not in the policy; the default for unlisted tools is ' + d + '.'); }
  else if (rule.action !== 'allow') add(rule.action, 'tool-rule', 'The policy sets "' + tool + '" to ' + rule.action + '.');
  if (rule && rule.action === 'deny') return finish();
  const r = rule || {};
  // ---- paths
  const pathKeys = (r.pathArgs || PATH_KEYS).map((k) => k.toLowerCase());
  walkStrings(args, (v, p) => {
    if (!pathKeys.includes(keyOf(p))) return; if (/^https?:/i.test(v)) return;
    if (/\0/.test(v)) { add('deny', 'null-byte', 'Path contains a null byte.', p); return; }
    const np = normalizePath(v, ctx.cwd || '/workspace');
    if (/(^|\/)\.\.(\/|$)/.test(v.replace(/\\/g, '/'))) add(r.paths && !pathMatch(np, r.paths) ? 'deny' : 'require-approval', 'path-traversal', '"' + v + '" climbs out with ".." (resolves to ' + np + ').', p);
    if (r.denyPaths && pathMatch(np, r.denyPaths)) add('deny', 'path-denied', np + ' matches a denied path.', p);
    else if (r.paths && !pathMatch(np, r.paths)) add('deny', 'path-not-allowed', np + ' is outside the allowed paths (' + r.paths.join(', ') + ').', p);
  });
  // ---- domains
  walkStrings(args, (v, p) => {
    const isUrlKey = URL_KEYS.includes(keyOf(p)); if (!isUrlKey && !/^https?:\/\//i.test(v)) return;
    const urls = isUrlKey ? [v] : (v.match(/https?:\/\/[^\s"'<>]+/gi) || []);
    for (const u of urls) {
      const pu = parseUrl(u); if (!pu) { if (isUrlKey) add('deny', 'bad-url', '"' + u + '" is not a valid URL.', p); continue; }
      if (!/^https?:$/.test(pu.protocol)) { add('deny', 'unsafe-scheme', pu.protocol + ' URLs are not allowed.', p); continue; }
      if (pu.username || pu.password) add('deny', 'userinfo-trick', 'The URL hides its real host (' + pu.hostname + ') behind an "@".', p);
      if (r.domains && isUrlKey && !hostAllowed(pu.hostname, r.domains)) add('deny', 'domain-not-allowed', pu.hostname + ' is not on the allowed domains (' + r.domains.join(', ') + ').', p);
      if (/^\d+\.\d+\.\d+\.\d+$/.test(pu.hostname) && /^(10|127|169\.254|192\.168|172\.(1[6-9]|2\d|3[01]))\./.test(pu.hostname)) add('deny', 'private-network', pu.hostname + ' is a private or metadata address.', p);
    }
  });
  // ---- recipients
  if (r.recipients || kind === 'email' || kind === 'email-draft' || kind === 'message') {
    walkStrings(args, (v, p) => {
      if (!RCPT_KEYS.includes(keyOf(p))) return;
      for (const e of emailsIn(v)) if (r.recipients && !matchAny(e, r.recipients)) add(r.unknownRecipient || 'require-approval', 'recipient-not-allowed', e + ' is not on the recipient allowlist.', p);
    });
  }
  // ---- amounts, limits and budgets
  walkStrings(args, (v, p) => { if (AMOUNT_KEYS.includes(keyOf(p))) { const a = parseAmount(v); if (isFinite(a)) amount = isFinite(amount) ? amount + a : a; } });
  if (isFinite(amount)) {
    if (amount < 0) add('deny', 'negative-amount', 'Negative amounts are not allowed.');
    if (r.hardLimit != null && amount > r.hardLimit) add('deny', 'over-hard-limit', '$' + amount + ' is over the hard limit of $' + r.hardLimit + '.');
    else if (r.maxAmount != null && amount > r.maxAmount) add(r.overLimit || 'require-approval', 'over-limit', '$' + amount + ' is over the $' + r.maxAmount + ' limit.');
    if (r.budget) { const spent = spentIn(st, tool, r.budget.per, now); if (spent + amount > r.budget.amount) add('require-approval', 'over-budget', '$' + spent + ' already spent this ' + (r.budget.per || 'session') + '; $' + amount + ' more would pass the $' + r.budget.amount + ' budget.'); }
  } else if (kind === 'payment' && (r.maxAmount != null || r.budget)) add('require-approval', 'amount-unknown', 'Could not read the amount, so the limit cannot be checked.');
  // ---- commands
  const cmdKeys = (r.commandArgs || COMMAND_ARG_KEYS).map((k) => k.toLowerCase());
  const commandLike = kind === 'shell' || kind === 'sql' || kind === 'deploy' || kind === 'git' || !!r.commands || !!r.sql;
  walkStrings(args, (v, p) => {
    if (!cmdKeys.includes(keyOf(p)) && !(commandLike && Object.keys(args).length === 1)) return;
    if (kind === 'sql' || r.sql) { if (r.sql === 'read-only') { const ro = sqlReadOnly(v); if (!ro.ok) add('deny', 'sql-not-read-only', 'Only read queries are allowed (' + ro.reason + ').', p); } }
    for (const h of dangerousCommand(v)) add(h.severity === 'critical' ? 'deny' : (r.dangerous || 'require-approval'), 'dangerous:' + h.id, h.why, p);
    if (r.dangerous === 'deny') for (const x of reasons) if (x.code.startsWith('dangerous:') && x.severity !== 'deny') { x.severity = 'deny'; action = 'deny'; }
    if (r.commands && kind !== 'sql') {
      for (const seg of shellSegments(v)) { const ok = r.commands.some((c) => seg === c || seg.startsWith(c + ' ')); if (!ok) add(r.otherCommands || 'require-approval', 'command-not-allowed', '"' + seg.split(/\s+/).slice(0, 3).join(' ') + '" is not an allowed command.', p); }
    }
  });
  if (r.denyArgs) walkStrings(args, (v, p) => { for (const re of r.denyArgs) if (new RegExp(re, 'i').test(v)) add('deny', 'denied-argument', 'Argument matches the denied pattern /' + re + '/.', p); });
  // ---- rate limits
  const lim = r.rateLimit || (policy.tools && policy.tools.rateLimit);
  if (lim) { const recent = (r.rateLimit ? (st.calls[tool] || []) : st.all).filter((t) => now - t < lim.per * 1000).length; if (recent >= lim.max) add('deny', 'rate-limit', recent + ' calls in the last ' + lim.per + 's (limit ' + lim.max + ').'); }
  // ---- sensitive action kinds
  if (['payment', 'email'].includes(kind)) reasons.push({ code: 'sensitive-action', severity: 'info', detail: kind === 'payment' ? 'Moves money (sandboxed here).' : 'Sends a message outside the system.' });
  // ---- taint and flagged context
  const sensitive = (policy.taint && policy.taint.sensitiveKinds) || SENSITIVE_KINDS;
  if (ctx.taint) {
    const tainted = ctx.taint.checkArgs(args);
    const seen = new Set();
    for (const t of tainted) { const k = t.arg + '|' + t.entity; if (seen.has(k)) continue; seen.add(k); const sev = (policy.taint && policy.taint.untrustedArgs) || 'require-approval'; if (sev !== 'allow' && (sensitive.includes(kind) || kind === 'web' || kind === 'other' || kind === 'email-draft')) add(sev, 'tainted-argument', '"' + t.arg + '" carries ' + (t.kind === 'phrase' ? t.entity : t.kind + ' ' + t.entity) + ' taken from untrusted ' + t.label + '.', t.arg); }
    const flagged = ctx.taint.flaggedSources();
    if (flagged.length && sensitive.includes(kind)) { const sev = (policy.taint && policy.taint.flaggedContext) || 'require-approval'; if (sev !== 'allow') add(sev, 'flagged-context', 'Instruction-like text was found in ' + flagged.map((f) => f.label).join(', ') + ' this turn, so a ' + kind + ' action needs a person.'); }
  }
  return finish();
  function finish() {
    const risk = action === 'deny' ? (reasons.some((x) => /critical|dangerous:(rm-rf-root|pipe-to-shell|disk-wipe|reverse-shell|secret-exfil|sql-drop|sql-truncate|sql-delete-all|infra-destroy)/.test(x.code)) ? 'critical' : 'high') : action === 'require-approval' ? 'medium' : reasons.some((x) => x.code === 'sensitive-action') ? 'medium' : 'low';
    const mode = policy.mode || 'enforce';
    const d = { tool, kind, action, reasons, risk, mode, amount: isFinite(amount) ? amount : null };
    if (mode === 'monitor' && action !== 'allow' && !reasons.some((x) => x.code === 'kill-switch')) { d.wouldBe = action; d.action = 'allow'; }
    return d;
  }
}
function spentIn(st, tool, per, now) { const win = per === 'hour' ? 3600e3 : per === 'day' ? 86400e3 : Infinity; return (st.spend[tool] || []).filter((x) => now - x.t < win).reduce((s, x) => s + x.amount, 0); }
/** Record that a call actually ran (for rate limits and budgets). */
export function recordCall(st, decision, now = Date.now()) {
  (st.calls[decision.tool] = st.calls[decision.tool] || []).push(now); st.all.push(now);
  if (decision.amount != null && decision.amount > 0) (st.spend[decision.tool] = st.spend[decision.tool] || []).push({ t: now, amount: decision.amount });
}
