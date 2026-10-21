import os
from pathlib import Path
import pytest

@pytest.fixture(autouse=True)
def isolate_q_table_runtime_globally(tmp_path, monkeypatch):
    """
    Auto-use fixture ensuring every test in the ai-engine test suite runs with an isolated
    temporary runtime Q-table path, guaranteeing zero accidental writes or mutations
    to the repository's protected ai-engine/runtime/q_table.json or ai-engine/models/q_table.json.
    """
    temp_runtime = tmp_path / "runtime" / "q_table.json"
    temp_runtime.parent.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("DEFAULT_RUNTIME_Q_TABLE_PATH", str(temp_runtime))


@pytest.fixture(autouse=True)
def allow_unregistered_test_models(monkeypatch):
    """
    Many tests build throwaway model directories without models/registry.json. Production refuses to load
    unregistered models (M4); tests opt in to the legacy first-match order explicitly. Tests of the refusal
    itself delete this variable.
    """
    monkeypatch.setenv("ALLOW_UNREGISTERED_MODELS", "1")
