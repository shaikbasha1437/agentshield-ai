"""Loads the rule tables, presets and benchmark cases exported from the JavaScript package."""
from __future__ import annotations

import functools
import json
from importlib import resources


@functools.lru_cache(maxsize=None)
def load_json(name: str):
    with resources.files(__package__).joinpath("data", name).open("r", encoding="utf-8") as f:
        return json.load(f)


@functools.lru_cache(maxsize=None)
def load_cases() -> tuple:
    with resources.files(__package__).joinpath("data", "cases.jsonl").open("r", encoding="utf-8") as f:
        return tuple(json.loads(line) for line in f if line.strip())


def rules() -> dict:
    return load_json("rules.json")
