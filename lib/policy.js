/* Policy model: parse YAML or JSON, validate with paths and line numbers, and fill in defaults.
   A policy says how strict each guard is and, per tool, what is allowed, denied or needs a person. */
import { parseYaml, toYaml } from './yaml.js';
import { DEFAULT_REDACT, DETECTORS } from './output.js';

export const ACTIONS = ['allow', 'deny', 'require-approval'];
export const KINDS = ['email', 'email-draft', 'payment', 'shell', 'sql', 'file-read', 'file-write', 'file-delete', 'web', 'search', 'calendar', 'ticket', 'deploy', 'git', 'message', 'other'];
export const SENSITIVE_KINDS = ['email', 'payment', 'shell', 'file-write', 'file-delete', 'deploy', 'git', 'message', 'sql'];
const REDACT_KINDS = DETECTORS.map((d) => d.kind);
export const DEFAULTS = {
  version: 1, name: 'untitled', description: '', mode: 'enforce', killSwitch: false,
  input: { injection: { block: 0.7, flag: 0.4 }, classifier: { enabled: false, threshold: 0.8 }, maxLength: 20000 },
  untrusted: { spotlight: 'delimit', quarantine: true, hiddenText: 'strip', flag: 0.4 },
  output: { redact: DEFAULT_REDACT.slice(), allowEmails: [], links: { allow: [], action: 'flag' }, exfiltration: 'block', leaks: 'block', schema: null },
  tools: { default: 'require-approval', rateLimit: null, rules: {} },
  taint: { untrustedArgs: 'require-approval', flaggedContext: 'require-approval', sensitiveKinds: SENSITIVE_KINDS.slice() },
  audit: { enabled: true, redact: true },
  tests: []
};
const RULE_KEYS = { action: 'action', kind: 'kind', description: 'string', paths: 'list', denyPaths: 'list', domains: 'list', sql: ['read-only', 'any'], maxAmount: 'number', hardLimit: 'number', overLimit: 'action', budget: 'object', recipients: 'list', unknownRecipient: 'action', commands: 'list', otherCommands: 'action', dangerous: 'action', denyArgs: 'list', rateLimit: 'object', trustOutput: 'boolean', commandArgs: 'list', pathArgs: 'list' };
const clone = (x) => (x === undefined ? undefined : JSON.parse(JSON.stringify(x)));
const isObj = (x) => x && typeof x === 'object' && !Array.isArray(x);
function merge(base, over) { if (!isObj(over)) return over === undefined ? clone(base) : clone(over); const out = clone(base) || {}; for (const [k, v] of Object.entries(over)) out[k] = isObj(v) && isObj(out[k]) ? merge(out[k], v) : clone(v); return out; }
/** Parse policy text (YAML or JSON). Returns { policy, errors, warnings, raw }. */
export function parsePolicy(text) {
  const src = String(text ?? '');
  let raw = null; let lines = {}; const errors = [];
  const t = src.trim();
  if (!t) return { policy: null, errors: [{ path: '', line: null, message: 'The policy is empty.' }], warnings: [], raw: null };
  if (t[0] === '{') { try { raw = JSON.parse(t); } catch (e) { errors.push({ path: '', line: null, message: 'Invalid JSON: ' + e.message }); } }
  else { const r = parseYaml(src); raw = r.value; lines = r.lines; for (const e of r.errors) errors.push({ path: '', line: e.line, message: e.message }); }
  if (errors.length) return { policy: null, errors, warnings: [], raw };
  const v = validatePolicy(raw, lines); return { policy: v.errors.length ? null : v.policy, errors: v.errors, warnings: v.warnings, raw };
}
export function validatePolicy(raw, lines = {}) {
  const errors = []; const warnings = [];
  const at = (path) => lines[path] ?? lines[path.replace(/\.[^.[\]]+$/, '')] ?? null;
  const err = (path, message) => errors.push({ path, line: at(path), message });
  const warn = (path, message) => warnings.push({ path, line: at(path), message });
  if (!isObj(raw)) { err('', 'A policy must be a map of settings (key: value).'); return { errors, warnings, policy: null }; }
  const known = Object.keys(DEFAULTS);
  for (const k of Object.keys(raw)) if (!known.includes(k)) warn(k, 'Unknown setting "' + k + '" is ignored.');
  if (raw.version != null && raw.version !== 1) err('version', 'Only version 1 is supported.');
  if (raw.mode != null && !['enforce', 'monitor', 'dry-run'].includes(raw.mode)) err('mode', 'mode must be enforce, monitor or dry-run.');
  if (raw.killSwitch != null && typeof raw.killSwitch !== 'boolean') err('killSwitch', 'killSwitch must be true or false.');
  const num01 = (path, v) => { if (v != null && (typeof v !== 'number' || v < 0 || v > 1)) err(path, 'Must be a number from 0 to 1.'); };
  const list = (path, v) => { if (v != null && (!Array.isArray(v) || v.some((x) => typeof x !== 'string'))) err(path, 'Must be a list of strings.'); };
  const enumv = (path, v, opts) => { if (v != null && !opts.includes(v)) err(path, 'Must be one of: ' + opts.join(', ') + '.'); };
  const inp = raw.input || {}; if (raw.input != null && !isObj(raw.input)) err('input', 'input must be a map.');
  if (inp.injection != null) { if (!isObj(inp.injection)) err('input.injection', 'Use { block: 0.7, flag: 0.4 }.'); else { num01('input.injection.block', inp.injection.block); num01('input.injection.flag', inp.injection.flag); if (inp.injection.block != null && inp.injection.flag != null && inp.injection.flag > inp.injection.block) err('input.injection.flag', 'flag must not be higher than block.'); } }
  if (inp.classifier != null && !isObj(inp.classifier)) err('input.classifier', 'Use { enabled: true, threshold: 0.8 }.'); else if (inp.classifier) num01('input.classifier.threshold', inp.classifier.threshold);
  if (inp.maxLength != null && !(Number.isInteger(inp.maxLength) && inp.maxLength > 0)) err('input.maxLength', 'Must be a positive whole number.');
  const un = raw.untrusted || {};
  enumv('untrusted.spotlight', un.spotlight, ['delimit', 'datamark', 'off']); enumv('untrusted.hiddenText', un.hiddenText, ['strip', 'flag', 'keep']); num01('untrusted.flag', un.flag);
  if (un.quarantine != null && typeof un.quarantine !== 'boolean') err('untrusted.quarantine', 'Must be true or false.');
  const out = raw.output || {};
  list('output.redact', out.redact); for (const [i, k] of (Array.isArray(out.redact) ? out.redact : []).entries()) if (!REDACT_KINDS.includes(k)) err('output.redact[' + i + ']', 'Unknown kind "' + k + '". Known: ' + REDACT_KINDS.join(', ') + '.');
  list('output.allowEmails', out.allowEmails);
  if (out.links != null) { if (!isObj(out.links)) err('output.links', 'Use { allow: [...], action: flag }.'); else { list('output.links.allow', out.links.allow); enumv('output.links.action', out.links.action, ['flag', 'strip', 'block']); } }
  enumv('output.exfiltration', out.exfiltration, ['block', 'flag']); enumv('output.leaks', out.leaks, ['block', 'flag']);
  if (out.schema != null && !isObj(out.schema)) err('output.schema', 'schema must be a JSON-schema map or null.');
  const tools = raw.tools || {}; if (raw.tools != null && !isObj(raw.tools)) err('tools', 'tools must be a map.');
  enumv('tools.default', tools.default, ACTIONS);
  const rl = (path, v) => { if (v == null) return; if (!isObj(v) || !(Number.isInteger(v.max) && v.max > 0) || !(typeof v.per === 'number' && v.per > 0)) err(path, 'Use { max: 10, per: 60 } (calls per seconds).'); };
  rl('tools.rateLimit', tools.rateLimit);
  if (tools.rules != null && !isObj(tools.rules)) err('tools.rules', 'rules must be a map of tool name to rule.');
  for (const [name, r] of Object.entries(isObj(tools.rules) ? tools.rules : {})) {
    const p = 'tools.rules.' + name;
    if (!/^[\w.:\-/]+$/.test(name)) err(p, 'Tool names may use letters, digits, _ . : - and /.');
    if (typeof r === 'string') { enumv(p, r, ACTIONS); continue; }
    if (!isObj(r)) { err(p, 'A rule is a map, or just allow / deny / require-approval.'); continue; }
    for (const [k, v] of Object.entries(r)) {
      const t = RULE_KEYS[k]; const pk = p + '.' + k;
      if (!t) { warn(pk, 'Unknown rule setting "' + k + '" is ignored.'); continue; }
      if (t === 'action') enumv(pk, v, ACTIONS); else if (t === 'kind') enumv(pk, v, KINDS); else if (t === 'list') list(pk, v); else if (t === 'number') { if (typeof v !== 'number' || v < 0) err(pk, 'Must be a number of at least 0.'); } else if (t === 'boolean') { if (typeof v !== 'boolean') err(pk, 'Must be true or false.'); } else if (t === 'string') { if (typeof v !== 'string') err(pk, 'Must be text.'); } else if (Array.isArray(t)) enumv(pk, v, t);
    }
    if (r.budget != null) { if (!isObj(r.budget) || typeof r.budget.amount !== 'number' || r.budget.amount < 0) err(p + '.budget', 'Use { amount: 500, per: session } (per: session, hour or day).'); else enumv(p + '.budget.per', r.budget.per, ['session', 'hour', 'day']); }
    rl(p + '.rateLimit', r.rateLimit);
    if (r.maxAmount != null && r.hardLimit != null && r.hardLimit < r.maxAmount) err(p + '.hardLimit', 'hardLimit must be at least maxAmount.');
    for (const [i, re] of (Array.isArray(r.denyArgs) ? r.denyArgs : []).entries()) { try { new RegExp(re, 'i'); } catch (e) { err(p + '.denyArgs[' + i + ']', 'Not a valid regular expression: ' + e.message); } }
    if (r.action === 'deny' && Object.keys(r).length > 1) warn(p, 'This tool is denied, so its other settings never apply.');
  }
  const ta = raw.taint || {}; enumv('taint.untrustedArgs', ta.untrustedArgs, ACTIONS); enumv('taint.flaggedContext', ta.flaggedContext, ACTIONS); list('taint.sensitiveKinds', ta.sensitiveKinds);
  for (const [i, k] of (Array.isArray(ta.sensitiveKinds) ? ta.sensitiveKinds : []).entries()) if (!KINDS.includes(k)) err('taint.sensitiveKinds[' + i + ']', 'Unknown kind "' + k + '".');
  if (raw.audit != null && !isObj(raw.audit)) err('audit', 'audit must be a map.');
  if (raw.tests != null) {
    if (!Array.isArray(raw.tests)) err('tests', 'tests must be a list.');
    else raw.tests.forEach((t, i) => { const p = 'tests[' + i + ']'; if (!isObj(t)) { err(p, 'Each test is a map.'); return; } const n = ['input', 'call', 'output', 'untrusted'].filter((k) => t[k] != null).length; if (n !== 1) err(p, 'A test needs exactly one of input, untrusted, output or call.'); if (t.call != null && (!isObj(t.call) || typeof t.call.tool !== 'string')) err(p + '.call', 'Use { tool: name, args: { ... } }.'); if (!['allow', 'deny', 'require-approval', 'block', 'flag', 'redact', 'quarantine'].includes(t.expect)) err(p + '.expect', 'expect must be allow, deny, require-approval, block, flag, redact or quarantine.'); });
  }
  if (!errors.length) {
    const tr = (raw.tools && raw.tools.rules) || {}; const names = Object.keys(tr);
    if ((raw.tools && raw.tools.default) === 'allow' && !names.some((n) => (isObj(tr[n]) ? tr[n].action : tr[n]) === 'deny')) warn('tools.default', 'Unknown tools are allowed and nothing is denied. Consider require-approval as the default.');
    if (raw.mode === 'monitor') warn('mode', 'Monitor mode logs what would be blocked but blocks nothing.');
    if (raw.killSwitch === true) warn('killSwitch', 'The kill switch is on: every tool call is denied.');
  }
  return { errors, warnings, policy: errors.length ? null : normalizePolicy(raw) };
}
export function normalizePolicy(raw) {
  const p = merge(DEFAULTS, raw || {});
  const rules = {};
  for (const [name, r] of Object.entries(p.tools.rules || {})) rules[name] = typeof r === 'string' ? { action: r } : Object.assign({ action: 'allow' }, r);
  p.tools.rules = rules;
  if (raw && raw.output && Array.isArray(raw.output.redact)) p.output.redact = raw.output.redact.slice();
  if (raw && raw.taint && Array.isArray(raw.taint.sensitiveKinds)) p.taint.sensitiveKinds = raw.taint.sensitiveKinds.slice();
  return p;
}
export function policyToYaml(p) { return toYaml(p) + '\n'; }
export function policyToJson(p) { return JSON.stringify(p, null, 2) + '\n'; }
