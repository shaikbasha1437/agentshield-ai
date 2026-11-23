// Type declarations for agentshield-guardrails. The runtime is plain JavaScript (ES modules, no dependencies).

export type Verdict = 'allow' | 'flag' | 'block';
export type ToolAction = 'allow' | 'deny' | 'require-approval';
export type Mode = 'enforce' | 'monitor' | 'dry-run';
export type ToolKind = 'email' | 'email-draft' | 'payment' | 'shell' | 'sql' | 'file-read' | 'file-write' | 'file-delete' | 'web' | 'search' | 'calendar' | 'ticket' | 'deploy' | 'git' | 'message' | 'other';
export type SourceKind = 'web' | 'email' | 'doc' | 'tool' | 'rag' | (string & {});

export interface RuleHit { rule: string; category: string; weight: number; effective: number; layer: string; match: string; why: string; note: string; dampened?: boolean; }
export interface Detection { score: number; verdict: Verdict; hits: RuleHit[]; signals: Record<string, unknown>; ms?: number; }
export interface InputDecision extends Detection { action: Verdict; wouldBe?: 'block'; classifier?: ClassifierResult; }
export interface ConversationDecision { verdict: Verdict; score: number; hits: RuleHit[]; perTurn: { verdict: Verdict; score: number }[]; splitAcrossTurns: boolean; ms: number; action: Verdict; }
export interface HiddenFinding { kind: string; text: string; detail: string; }
export interface IngestResult {
  verdict: 'clean' | 'flagged' | 'quarantined'; score: number; hits: RuleHit[];
  flagged: { text: string; index: number; score: number; verdict: Verdict; hits: RuleHit[] }[];
  removed: number; hidden: HiddenFinding[]; hiddenInstructions: { kind: string; detail: string; text: string; score: number; rules: string[] }[];
  hiddenStripped: boolean; wrapped: string; text: string; sourceId: string; ms: number;
}
export interface UrlIssue { code: string; severity: 'block' | 'flag'; detail: string; }
export interface UrlCheck { url: string; kind: string; index: number; raw: string; text?: string; host?: string; issues: UrlIssue[]; }
export interface Redaction { kind: string; label: string; preview: string; }
export interface OutputDecision { action: 'allow' | 'redact' | 'block'; text: string; redactions: Redaction[]; leaks: { kind: string; detail: string }[]; urls: UrlCheck[]; schema: SchemaResult | null; reasons: string[]; ms: number; wouldBe?: 'redact' | 'block'; }
export interface ToolCall { tool: string; args?: Record<string, unknown>; }
export interface Reason { code: string; severity: ToolAction | 'info'; detail: string; arg?: string; }
export interface ToolDecision { tool: string; kind: ToolKind; action: ToolAction; reasons: Reason[]; risk: 'low' | 'medium' | 'high' | 'critical'; mode: Mode; amount: number | null; wouldBe?: ToolAction; approvedBy?: string; ms?: number; }
export interface ExecuteResult { status: 'ok' | 'denied' | 'pending' | 'dry-run'; decision: ToolDecision; result?: unknown; id?: string; ingested?: IngestResult | null; }
export interface SchemaResult { ok: boolean; value: unknown; errors: string[]; }

export interface ToolRule {
  action?: ToolAction; kind?: ToolKind; description?: string; paths?: string[]; denyPaths?: string[]; domains?: string[]; sql?: 'read-only' | 'any';
  maxAmount?: number; hardLimit?: number; overLimit?: ToolAction; budget?: { amount: number; per?: 'session' | 'hour' | 'day' };
  recipients?: string[]; unknownRecipient?: ToolAction; commands?: string[]; otherCommands?: ToolAction; dangerous?: ToolAction; denyArgs?: string[];
  rateLimit?: { max: number; per: number }; trustOutput?: boolean; commandArgs?: string[]; pathArgs?: string[];
}
export interface Policy {
  version?: 1; name?: string; description?: string; mode?: Mode; killSwitch?: boolean;
  input?: { injection?: { block?: number; flag?: number }; classifier?: { enabled?: boolean; threshold?: number }; maxLength?: number };
  untrusted?: { spotlight?: 'delimit' | 'datamark' | 'off'; quarantine?: boolean; hiddenText?: 'strip' | 'flag' | 'keep'; flag?: number };
  output?: { redact?: string[]; allowEmails?: string[]; links?: { allow?: string[]; action?: 'flag' | 'strip' | 'block' }; exfiltration?: 'block' | 'flag'; leaks?: 'block' | 'flag'; schema?: Record<string, unknown> | null };
  tools?: { default?: ToolAction; rateLimit?: { max: number; per: number } | null; rules?: Record<string, ToolRule | ToolAction> };
  taint?: { untrustedArgs?: ToolAction; flaggedContext?: ToolAction; sensitiveKinds?: ToolKind[] };
  audit?: { enabled?: boolean; redact?: boolean };
  tests?: Record<string, unknown>[];
}
export interface PolicyError { path: string; line: number | null; message: string; }
export interface ClassifierResult { label: 'injection' | 'benign' | 'unknown' | 'error'; score: number; confidence?: number; reason: string; ms?: number; }

export interface GuardOptions {
  /** A policy object, or YAML/JSON policy text (for example PRESETS.balanced.yaml). */
  policy?: Policy | string;
  /** Exact strings (such as your own API keys) that are always removed from output and the audit log. */
  secrets?: string[];
  /** Canary token planted in the system prompt; false disables it. */
  canary?: string | false;
  systemPrompt?: string;
  sensitiveValues?: string[];
  classifier?: (text: string) => Promise<ClassifierResult>;
  cwd?: string;
  audit?: AuditLog;
  onApproval?: (item: ApprovalItem) => void;
  rand?: () => number;
  clock?: () => string;
}
export interface ApprovalItem { id: string; call: ToolCall; decision: ToolDecision; diff: unknown; createdAt: string; status: 'pending' | 'approved' | 'denied'; by?: string; decidedAt?: string; }
export interface Guard {
  readonly policy: Policy;
  audit: AuditLog; taint: TaintTracker; state: FirewallState; canary: string | null;
  setPolicy(p: Policy | string): Policy;
  kill(on?: boolean): boolean;
  systemPromptAddendum(): string;
  newTurn(): void;
  trust(text: string): void;
  checkInput(text: string, opt?: { role?: 'user' | 'tool'; trust?: boolean }): InputDecision;
  checkInputAsync(text: string, opt?: { classifier?: GuardOptions['classifier'] }): Promise<InputDecision>;
  checkConversation(turns: { role?: string; content?: string; text?: string }[], opt?: { window?: number }): ConversationDecision;
  ingest(content: string, meta?: { source?: SourceKind; label?: string; format?: 'html' | 'markdown' | 'text'; id?: string; trusted?: boolean }): IngestResult;
  checkOutput(text: string, opt?: { systemPrompt?: string; canaries?: string[]; sensitive?: string[]; schema?: Record<string, unknown>; blockMessage?: string }): OutputDecision;
  checkToolCall(call: ToolCall, opt?: { log?: boolean; now?: number; cwd?: string }): ToolDecision;
  execute(call: ToolCall, executor?: (args: Record<string, unknown>, call: ToolCall) => unknown, opt?: { preview?: (call: ToolCall) => unknown; dryRun?: boolean; ingest?: boolean; decision?: ToolDecision }): Promise<ExecuteResult>;
  approvals: {
    list(): ApprovalItem[]; history(): ApprovalItem[]; get(id: string): ApprovalItem | null;
    approve(id: string, opt?: { by?: string; note?: string; executor?: (args: Record<string, unknown>, call: ToolCall) => unknown }): Promise<ExecuteResult>;
    deny(id: string, opt?: { by?: string; note?: string }): ApprovalItem; restore(item: ApprovalItem): ApprovalItem; clear(): void;
  };
  wrapOpenAI<T>(client: T, opt?: { onBlock?: 'throw' | 'refuse'; addSystemNote?: boolean; isApproved?: (call: ToolCall) => boolean }): T;
  wrapAnthropic<T>(client: T, opt?: { onBlock?: 'throw' | 'refuse'; addSystemNote?: boolean; isApproved?: (call: ToolCall) => boolean }): T;
  wrapMcpClient<T>(client: T, opt?: { preview?: (call: ToolCall) => unknown }): T;
  wrapTools<T>(tools: T[], opt?: { preview?: (call: ToolCall) => unknown }): T[];
}
export function createGuard(o?: GuardOptions): Guard;
export class GuardrailError extends Error { detail?: unknown; constructor(message: string, detail?: unknown); }
export function wrapOpenAI<T>(g: Guard, client: T, opt?: object): T;
export function wrapAnthropic<T>(g: Guard, client: T, opt?: object): T;
export function wrapMcpClient<T>(g: Guard, client: T, opt?: object): T;
export function wrapTools<T>(g: Guard, tools: T[], opt?: object): T[];

export function detect(text: string, o?: { block?: number; flag?: number; source?: string; decode?: boolean }): Detection;
export function scanSentences(text: string, o?: { block?: number; flag?: number; source?: string }): IngestResult['flagged'];
export function explain(result: Detection): string;
export const RULES: { id: string; cat: string; w: number; re: RegExp; why: string }[];
export function scanHidden(content: string, o?: { format?: 'html' | 'markdown' | 'text' }): { format: string; findings: HiddenFinding[]; visible: string; hidden: string };
export function htmlToText(html: string): string;
export function spotlight(text: string, o?: { mode?: 'delimit' | 'datamark' | 'off'; source?: string; label?: string; note?: string; id?: string; rand?: () => number }): string;
export function neutralize(text: string): string;
export const SPOTLIGHT_NOTE: string;
export function redact(text: string, o?: { kinds?: string[]; allowEmails?: string[]; allowDomains?: string[]; secrets?: string[]; style?: 'kind' }): { text: string; redactions: Redaction[] };
export function findSensitive(text: string, o?: { kinds?: string[]; allowEmails?: string[]; allowDomains?: string[] }): { kind: string; label: string; start: number; end: number; value: string }[];
export function leakCheck(output: string, o?: { canaries?: string[]; systemPrompt?: string }): { kind: string; detail: string }[];
export function checkUrls(text: string, o?: { allowDomains?: string[]; allowEmails?: string[]; linkAction?: 'flag' | 'strip' | 'block'; sensitive?: string[] }): UrlCheck[];
export function extractUrls(text: string): Omit<UrlCheck, 'issues' | 'host'>[];
export function enforceSchema(text: string, schema: Record<string, unknown>): SchemaResult;
export function validateSchema(value: unknown, schema: Record<string, unknown>, path?: string): string[];
export function makeCanary(rand?: () => number): string;
export function luhn(digits: string): boolean;
export const DETECTORS: { kind: string; label: string; re: RegExp; value?: number; check?: (m: string) => boolean }[];

export interface FirewallState { calls: Record<string, number[]>; spend: Record<string, { t: number; amount: number }[]>; all: number[]; }
export function checkToolCall(policy: Policy, call: ToolCall, ctx?: { taint?: TaintTracker; state?: FirewallState; now?: number; cwd?: string }): ToolDecision;
export function guessKind(name: string): ToolKind;
export function normalizePath(p: string, cwd?: string): string;
export function createFirewallState(): FirewallState;
export function recordCall(st: FirewallState, decision: ToolDecision, now?: number): void;
export function dangerousCommand(cmd: string): { id: string; severity: 'critical' | 'high'; why: string }[];
export function sqlReadOnly(q: string): { ok: boolean; reason: string; statements: number };
export function sqlStatements(q: string): string[];
export const COMMAND_PATTERNS: { id: string; severity: 'critical' | 'high'; re: RegExp; why: string }[];

export class TaintTracker {
  sources: { id: string; label: string; kind: string; entities: Map<string, string>; grams: Set<string>; flagged: boolean }[];
  addTrusted(text: string): void;
  addUntrusted(text: string, meta?: { id?: string; label?: string; kind?: string; flagged?: boolean }): TaintTracker['sources'][number];
  markFlagged(id: string): void;
  flaggedSources(): TaintTracker['sources'];
  isTrustedValue(v: string): boolean;
  checkValue(value: string): { entity: string; kind: string; source: string; label: string }[];
  checkArgs(args: unknown): { arg: string; entity: string; kind: string; source: string; label: string }[];
  reset(): void;
}
export function extractEntities(text: string): Map<string, string>;

export interface AuditEntry { seq: number; ts: string; type: string; data: unknown; prev: string; hash: string; }
export class AuditLog {
  entries: AuditEntry[];
  constructor(o?: { redact?: boolean; secrets?: string[]; allowEmails?: string[]; now?: () => string; onAppend?: (e: AuditEntry) => void });
  append(type: string, data: unknown): AuditEntry;
  verify(): { ok: boolean; count: number; brokenAt: number | null; reason: string };
  head(): string;
  toJSON(): { format: string; head: string; count: number; entries: AuditEntry[] };
  static from(json: unknown, o?: object): AuditLog;
}
export function verifyChain(entries: AuditEntry[]): { ok: boolean; count: number; brokenAt: number | null; reason: string };
export function canonicalJson(v: unknown): string;
export function redactDeep<T>(v: T, o?: object): T;
export const GENESIS: string;

export function parsePolicy(text: string): { policy: Policy | null; errors: PolicyError[]; warnings: PolicyError[]; raw: unknown };
export function validatePolicy(raw: unknown, lines?: Record<string, number>): { policy: Policy | null; errors: PolicyError[]; warnings: PolicyError[] };
export function normalizePolicy(raw: Policy): Policy;
export function policyToYaml(p: Policy): string;
export function policyToJson(p: Policy): string;
export const DEFAULTS: Policy;
export const KINDS: ToolKind[];
export const PRESETS: Record<string, { label: string; description: string; yaml: string }>;
export const PRESET_IDS: string[];
export function runPolicyTests(policy: Policy, tests?: Record<string, unknown>[], o?: { canary?: string; systemPrompt?: string }): { index: number; name: string; expect: string; got: string; pass: boolean; detail: string }[];
export function classifierMessages(text: string): { role: 'system' | 'user'; content: string }[];
export function parseClassifierReply(reply: string): ClassifierResult;
export function makeClassifier(call: (messages: { role: string; content: string }[]) => Promise<string>): (text: string) => Promise<ClassifierResult>;
export function parseYaml(text: string): { value: unknown; errors: { line: number; message: string }[]; lines: Record<string, number> };
export function toYaml(v: unknown): string;
export function lineDiff(before: string | null | undefined, after: string): { op: ' ' | '+' | '-'; text: string }[];
export function sha256(s: string): string;
export const normalize: Record<string, unknown>;
