"""agentshield-guardrails: explainable guardrails for LLM agents.

Prompt-injection and jailbreak detection, hidden-text stripping and spotlighting for untrusted content, output
redaction and exfiltration checks, and a policy firewall for tool calls with approvals, taint tracking and a
hash-chained audit log. Pure Python, no required dependencies. The rules are shared with the JavaScript package
of the same name, and a parity test checks that both give identical verdicts on the benchmark."""
from __future__ import annotations

from .audit import GENESIS, AuditLog, canonical_json, redact_deep, verify_chain
from .bench import classification_metrics, metrics_table, run_benchmark, run_case
from .dangerous import COMMAND_PATTERNS, dangerous_command, shell_segments, sql_read_only, sql_statements
from .extras import classifier_messages, make_classifier, parse_classifier_reply, run_policy_tests
from .firewall import check_tool_call, create_firewall_state, guess_kind, normalize_path, record_call
from .guard import Guard, GuardrailError, create_guard
from .hidden import html_to_text, scan_hidden
from .injection import RULES, detect, explain, scan_sentences
from .output import DETECTORS, check_urls, enforce_schema, extract_urls, find_sensitive, leak_check, luhn, make_canary, redact, validate_schema
from .policy import DEFAULTS, KINDS, PRESET_IDS, normalize_policy, parse_policy, preset, preset_info, validate_policy
from .spotlight import SPOTLIGHT_NOTE, neutralize, spotlight
from .taint import TaintTracker, extract_entities

__version__ = "0.2.0"
__all__ = [
    "AuditLog", "COMMAND_PATTERNS", "DEFAULTS", "DETECTORS", "GENESIS", "Guard", "GuardrailError", "KINDS", "PRESET_IDS", "RULES", "SPOTLIGHT_NOTE",
    "TaintTracker", "canonical_json", "check_tool_call", "check_urls", "classification_metrics", "classifier_messages", "create_firewall_state",
    "create_guard", "dangerous_command", "detect", "enforce_schema", "explain", "extract_entities", "extract_urls", "find_sensitive", "guess_kind",
    "html_to_text", "leak_check", "luhn", "make_canary", "make_classifier", "metrics_table", "neutralize", "normalize_path", "normalize_policy",
    "parse_classifier_reply", "parse_policy", "preset", "preset_info", "record_call", "redact", "redact_deep", "run_benchmark", "run_case",
    "run_policy_tests", "scan_hidden", "scan_sentences", "shell_segments", "spotlight", "sql_read_only", "sql_statements", "validate_policy",
    "validate_schema", "verify_chain", "__version__",
]
