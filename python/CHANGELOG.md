# Changelog

All notable changes to the Python package `quadward` are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow [Semantic Versioning](https://semver.org/). The version number moves in step with the npm package.

## [0.2.0] - 2026-11-24

The project was previously developed under the working name AgentShield.

### Added
- First Python release: a pure-Python port of the JavaScript library. It includes the injection detector and normaliser, hidden-text scanner, spotlighting, output checks, tool firewall, dangerous-command and SQL checks, taint tracking, YAML/JSON policies with the eight presets, the hash-chained audit log, the `Guard` class with approvals, and the benchmark runner.
- Type hints and a `py.typed` marker.
- The `quadward` command line, with `check`, `bench`, `test` and `presets`.
- Parity tests against golden outputs generated from the JavaScript package.
