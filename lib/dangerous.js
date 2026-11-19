/* Dangerous-command detection for shell, SQL, git, Kubernetes and cloud CLIs. Only command-like arguments are
   checked (command, cmd, script, query, sql ...), so a README that merely mentions "rm -rf build/" can be written
   to a file without tripping this. Each pattern carries a severity: critical (denied) or high (needs a person). */
const P = (id, severity, re, why) => ({ id, severity, re, why });
export const COMMAND_PATTERNS = [
  P('rm-rf-root', 'critical', /\brm\s+(?:-[a-z]*\s+)*-?-?[a-z]*(?:r[a-z]*f|f[a-z]*r|recursive)[a-z]*\b[^;&|\n]*?(?:\s\/(?:\s|$|\*)|\s\/\*|\s\.\/\*|\s~\/?(?:\s|$)|\s\$home\b|\s\*(?:\s|$)|\s\.\.?\/?(?:\s|$)|--no-preserve-root|\s\/(?:etc|usr|var|home|bin|boot|lib|opt|root|srv)\b\/?(?:\s|$))/i, 'Recursive force delete of the root, home, a system folder or everything in the current directory.'),
  P('rm-recursive', 'high', /\brm\s+(?:-[a-z]*\s+)*-[a-z]*r[a-z]*\b|\brm\s+--recursive\b|\bfind\b[^;\n]*\s-delete\b|\brmdir\s+\/s\b|\bremove-item\b[^;\n]*-recurse/i, 'Recursive delete.'),
  P('chmod-777', 'high', /\bchmod\s+(?:-[a-z]+\s+)*0?777\b|\bchmod\s+(?:-[a-z]+\s+)*[augo]*\+rwx\s+\//i, 'Makes files writable by everyone.'),
  P('chown-root-recursive', 'high', /\bchown\s+-r\s+\S+\s+\/(?:\s|$)/i, 'Recursive ownership change from the root.'),
  P('pipe-to-shell', 'critical', /\b(?:curl|wget|fetch|iwr|invoke-webrequest)\b[^|;&\n]*\|\s*(?:sudo\s+)?(?:ba|z|da|k|fi)?sh\b|\b(?:ba|z)?sh\s+(?:-c\s+)?["']?\$?\(\s*(?:curl|wget)\b|\b(?:ba|z)?sh\s+<\(\s*(?:curl|wget)|\biex\s*\(?[^;\n]*(?:downloadstring|iwr|invoke-webrequest)/i, 'Downloads a script and runs it unseen (curl | sh).'),
  P('decode-to-shell', 'critical', /\bbase64\s+(?:-d|--decode|-D)\b[^|\n]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b|\becho\s+[A-Za-z0-9+/=]{16,}\s*\|\s*base64\s+-d/i, 'Decodes hidden text and runs it as a script.'),
  P('disk-wipe', 'critical', /\bmkfs(?:\.\w+)?\b|\bdd\s+[^;\n]*\bof=\/dev\/(?:sd|nvme|hd|xvd|disk|mmcblk)|>\s*\/dev\/(?:sd|nvme|hd|xvd)[a-z]|\bwipefs\b|\bformat\s+[a-z]:/i, 'Formats or overwrites a disk.'),
  P('fork-bomb', 'critical', /:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/, 'A fork bomb.'),
  P('reverse-shell', 'critical', /\b(?:nc|ncat|netcat)\b[^;\n]*\s-[a-z]*e\s|\/dev\/tcp\/|\bbash\s+-i\s+>&|\bsocat\b[^;\n]*exec:/i, 'Opens a remote shell.'),
  P('secret-exfil', 'critical', /\b(?:cat|printenv|env|set|type|more|less|head|tail)\b[^|;\n]*\|\s*(?:curl|wget|nc|ncat|netcat|mail|sendmail)\b|\b(?:curl|wget)\b[^;\n]*(?:-d|--data(?:-binary|-raw)?|-F|--form|--upload-file|-T)\s*["']?@?[^\s"']*(?:\.env|id_rsa|id_ed25519|credentials|\.aws|\.ssh|secrets?|\.npmrc|\.netrc|passwd|shadow)/i, 'Sends secrets or environment variables to a remote host.'),
  P('history-wipe', 'high', /\bhistory\s+-c\b|>\s*~?\/?[\w/]*\.bash_history|\bshred\b|\bunset\s+histfile\b/i, 'Erases shell history (covers tracks).'),
  P('sudo', 'high', /(?:^|[;&|]\s*|\s)sudo\s+\S/i, 'Runs with root privileges.'),
  P('shutdown', 'high', /(?:^|[;&|]\s*|\s)(?:shutdown|reboot|halt|poweroff|init\s+0|systemctl\s+(?:poweroff|reboot|halt))\b/i, 'Shuts down or restarts the machine.'),
  P('firewall-off', 'high', /\biptables\s+-f\b|\bufw\s+disable\b|\bsetenforce\s+0\b|\bnetsh\s+advfirewall\s+set\s+\w+\s+state\s+off/i, 'Turns the firewall or SELinux off.'),
  P('kill-all', 'high', /\bkill(?:all)?\s+-9\s+(?:-1|1)\b|\bpkill\s+-9\s+-u\b/i, 'Kills every process.'),
  P('git-force-push', 'high', /\bgit\s+push\b[^;&|\n]*(?:\s-f\b|\s--force\b|\s--force-with-lease\b|\s\+[\w/-]+)/i, 'Force push rewrites shared history.'),
  P('git-force-push-main', 'critical', /\bgit\s+push\b[^;&|\n]*(?:\s-f\b|\s--force\b|\s\+)[^;&|\n]*\b(?:main|master|release|prod(?:uction)?)\b|\bgit\s+push\b[^;&|\n]*\+(?:main|master)\b/i, 'Force push to a protected branch.'),
  P('git-destructive', 'high', /\bgit\s+(?:reset\s+--hard|clean\s+-[a-z]*f[a-z]*|checkout\s+--\s+\.|branch\s+-d\s+-f|branch\s+-D|filter-branch|filter-repo|push\s+[^;\n]*--delete|push\s+\S+\s+:\S+|reflog\s+expire|gc\s+--prune=now)/, 'Discards commits, branches or work in progress.'),
  P('kubectl-delete', 'high', /\b(?:kubectl|oc)\s+delete\b/i, 'Deletes Kubernetes resources.'),
  P('kubectl-delete-all', 'critical', /\b(?:kubectl|oc)\s+delete\b[^;\n]*(?:--all\b|\s(?:ns|namespace|namespaces)\s|\s-A\b|--all-namespaces)/i, 'Deletes all resources or a whole namespace.'),
  P('scale-to-zero', 'high', /\b(?:kubectl|oc)\s+scale\b[^;&|\n]*--replicas[= ]0\b|\bscale\b[^;\n]*\bto\s+(?:0|zero)\b|desired[_-]?count[= ]0\b|--min-size[= ]0\b[^;\n]*--max-size[= ]0\b/i, 'Scales a service down to zero (an outage).'),
  P('infra-destroy', 'critical', /\bterraform\s+(?:destroy|apply\s+[^;\n]*-destroy)\b|\bpulumi\s+destroy\b|\bhelm\s+(?:uninstall|delete)\b|\baws\s+s3\s+(?:rm|rb)\b[^;\n]*(?:--recursive|--force)|\baws\s+\S+\s+delete-\w+|\bgcloud\b[^;\n]*\sdelete\b|\baz\s+group\s+delete\b|\bcdk\s+destroy\b/i, 'Destroys cloud infrastructure or data.'),
  P('sql-drop', 'critical', /\bdrop\s+(?:table|database|schema|index|view|user|role|collection)\b/i, 'Drops a table, database or other object.'),
  P('sql-truncate', 'critical', /\btruncate\s+(?:table\s+)?[\w."`[\]]+/i, 'Deletes every row in a table.'),
  P('sql-delete-all', 'critical', /\bdelete\s+from\s+[\w."`[\]]+\s*(?:;|$|--|\/\*)|\bdelete\s+from\s+[\w."`[\]]+\s+where\s+(?:1\s*=\s*1|true|'1'\s*=\s*'1')/i, 'DELETE without a real WHERE clause removes every row.'),
  P('sql-update-all', 'high', /\bupdate\s+[\w."`[\]]+\s+set\b(?![\s\S]*\bwhere\b)|\bupdate\s+[\w."`[\]]+\s+set\b[\s\S]*\bwhere\s+(?:1\s*=\s*1|true)\b/i, 'UPDATE without a WHERE clause changes every row.'),
  P('sql-delete', 'high', /\bdelete\s+from\b/i, 'Deletes rows.'),
  P('sql-alter', 'high', /\balter\s+(?:table|database|user|role)\b[^;\n]*\b(?:drop|rename|owner|password)\b/i, 'Changes a schema or account.'),
  P('sql-grant', 'high', /\b(?:grant|revoke)\s+(?:all|select|insert|update|delete|admin|superuser|\w+)\b[^;\n]*\b(?:to|from|on)\b/i, 'Changes database permissions.'),
  P('sql-file-access', 'critical', /\binto\s+(?:out|dump)file\b|\bload_file\s*\(|\bcopy\s+[\w."]+\s+(?:to|from)\s+(?:program|'\/)|\bxp_cmdshell\b|\battach\s+database\b/i, 'Reads or writes server files from SQL, or runs commands.')
];
export const COMMAND_ARG_KEYS = ['command', 'cmd', 'script', 'shell', 'query', 'sql', 'statement', 'args', 'argv', 'code', 'run', 'exec'];
/** Return matching dangerous patterns for a command string, most severe first, with the specific pattern
 *  removed when a broader one of the same family also matched. */
export function dangerousCommand(cmd) {
  const raw = String(cmd ?? ''); const sql = sqlStatements(raw).join(' ; ');
  const hits = COMMAND_PATTERNS.filter((p) => p.re.test(p.id.startsWith('sql-') ? sql : raw)).map((p) => ({ id: p.id, severity: p.severity, why: p.why }));
  const ids = new Set(hits.map((h) => h.id));
  const drop = new Set(); if (ids.has('rm-rf-root')) drop.add('rm-recursive'); if (ids.has('git-force-push-main')) drop.add('git-force-push'); if (ids.has('kubectl-delete-all')) drop.add('kubectl-delete'); if (ids.has('sql-delete-all')) drop.add('sql-delete');
  return hits.filter((h) => !drop.has(h.id)).sort((a, b) => (a.severity === b.severity ? 0 : a.severity === 'critical' ? -1 : 1));
}
export function stripSqlComments(s) { return String(s).replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/(^|\s)--[^\n]*/g, '$1'); }
/* SQL statement classification for read-only enforcement. String literals are blanked first so a value like
   'drop table' inside a WHERE clause does not count, and every statement in a batch is checked. */
export function sqlStatements(q) {
  const blanked = stripSqlComments(String(q ?? '')).replace(/'(?:[^']|'')*'/g, "''").replace(/"(?:[^"]|"")*"/g, '""');
  return blanked.split(';').map((x) => x.trim()).filter(Boolean);
}
const WRITE_KW = /\b(insert|update|delete|drop|alter|create|replace|truncate|attach|detach|grant|revoke|vacuum|reindex|merge|upsert|copy|call|exec|execute|lock|rename|comment\s+on|set\s+role)\b/i;
export function sqlReadOnly(q) {
  const st = sqlStatements(q); if (!st.length) return { ok: false, reason: 'empty query', statements: 0 };
  for (const s of st) {
    const first = (s.match(/^\(*\s*(\w+)/) || [])[1]?.toLowerCase();
    if (!['select', 'with', 'explain', 'show', 'describe', 'desc', 'pragma', 'values'].includes(first)) return { ok: false, reason: 'statement starts with ' + (first || '?').toUpperCase(), statements: st.length };
    if (first === 'pragma' && /=/.test(s)) return { ok: false, reason: 'PRAGMA that sets a value', statements: st.length };
    if (WRITE_KW.test(s.replace(/\b(created_at|updated_at|deleted_at|is_deleted|replaced_by|create_date|update_time)\b/gi, ''))) return { ok: false, reason: 'contains ' + s.match(WRITE_KW)[1].toUpperCase(), statements: st.length };
    if (/\binto\s+\w/i.test(s) && first === 'select') return { ok: false, reason: 'SELECT ... INTO writes a table', statements: st.length };
  }
  return { ok: true, reason: st.length > 1 ? st.length + ' read statements' : 'read-only', statements: st.length };
}
/* Split a shell line into simple commands (on ; && || | and newlines) for allowlisting by prefix. */
export function shellSegments(cmd) { return String(cmd ?? '').split(/\s*(?:;|&&|\|\||\||\n|`|\$\()\s*/).map((s) => s.trim().replace(/^\(+|\)+$/g, '')).filter(Boolean); }
