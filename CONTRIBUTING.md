# Contributing

Thanks for helping. Bug reports, missed attacks, false positives and new benchmark cases are all welcome.

## Ground rules

- **No real secrets or personal data.** Use `.example` domains, obviously fake keys and standard test card numbers. A hygiene test enforces this.
- **Every rule change needs a case.** If you add or change a detection rule, add a benchmark case that it catches. If it could cause false positives, also add a benign near-miss.
- **Keep JavaScript and Python identical.** `lib/` is the source of truth. The Python package reads the rule tables exported from it, and a parity test compares verdicts case by case.
- **Be honest about results.** Don't tune rules to a single case without saying so in the case's `note`. Missed attacks are documented, not hidden.

## Setup

```sh
git clone https://github.com/shaikbasha1437/agentshield-ai && cd agentshield-ai
npm test                                             # Node 18+ (CI uses Node 24); no dependencies to install
python -m venv .venv && . .venv/bin/activate
pip install -e "python[test]" && pytest python       # Python 3.9+
```

## Changing rules, presets or cases

1. Edit `lib/` (rules, presets) or `bench/cases.js` (cases).
2. Run `node scripts/export-data.mjs`. This regenerates:
   - `python/src/agentshield_guardrails/data/`;
   - the golden files in `python/tests/golden/`;
   - `dataset/data/`.
3. Run `npm test` and `pytest python`. If the Python port disagrees with JavaScript on a new pattern, the parity test names the case. Fix the translation in `python/src/agentshield_guardrails/_jsre.py` or the matching module.
4. Run `python dataset/eval.py` and update the numbers in the README if they changed.
5. Add a line to `lib/CHANGELOG.md` and `python/CHANGELOG.md`.

CI runs all of the above. It also checks that the exported files are up to date (`node scripts/export-data.mjs --check`).

## Proposing a benchmark case

Open an issue with the "New benchmark case" template, or add the case to `bench/cases.js` with:

- `kind`, `cat` and `stage`;
- the text;
- a one-line `note`.

New cases are added at the end so that existing IDs stay stable. The benchmark version (in `scripts/export-data.mjs`) is bumped when cases change.

## Pull requests

- Keep each change focused.
- Write commit messages that describe the change.
- By contributing, you agree that your code is released under MIT and your benchmark cases under CC-BY-4.0.
