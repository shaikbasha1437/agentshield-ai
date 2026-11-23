# Changelog

All notable changes to `agentshield-guardrails` (npm) are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [0.2.0] - unreleased

### Added
- Package metadata for npm under the name `agentshield-guardrails`: `exports` map, subpath entry points, `files` allow-list and provenance publishing.
- Hand-written TypeScript declarations (`index.d.ts`) covering every runtime export. A test checks that the declared and runtime export lists stay in sync.
- Rule tables for normalisation, compact matching and hidden-style detection are now exported. The Python port and the dataset export read them from here, so there is one source of truth.
- A pure-Python port (`agentshield-guardrails` on PyPI). A parity test checks that it gives identical verdicts, scores and explanations on all 257 benchmark cases under all eight presets.

### Changed
- The package was renamed from the working name `agentshield-guard`. A different project already uses that name on PyPI, so one name is now used on both registries.

## [0.1.0] - 2026-11

Initial version, used by the browser demo, CLI, proxy and GitHub Action in the repository. It was not published to a registry.
