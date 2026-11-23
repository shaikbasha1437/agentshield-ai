# Security policy

## Reporting a vulnerability

Please **do not** open a public issue for a security problem. Use GitHub's private vulnerability reporting instead: on the repository page, go to **Security → Report a vulnerability**. You will get a reply there, normally within a week.

Useful details to include:

- the package (npm or Python) and version, or the commit;
- the policy or preset in use;
- a minimal input that shows the problem;
- what you expected to happen.

## What counts

The following are **vulnerabilities**:

- a crash, hang or catastrophic regex backtracking triggered by crafted input;
- a way to make the firewall allow a call that the policy clearly denies, such as path-normalisation or SQL-splitting bypasses;
- tampering with the audit log that `verify()` does not detect;
- secrets passed in `secrets` that are not redacted;
- anything in the web app or proxy that leaks a user's API key.

The following are **not vulnerabilities**, but they are welcome as issues using the "Missed attack" template:

- a new paraphrase, language or encoding that the detection rules miss;
- a benign text that is flagged.

A rule-based guard cannot catch every attack, and the README says so. Missed attacks are tracked as benchmark cases.

## Supported versions

Only the latest release of each package receives fixes.
