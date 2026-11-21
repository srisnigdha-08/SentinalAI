"""Rank 8: test-isolation guards.

importlib.reload of a production module replaces its classes and functions while other modules keep references to
the old objects, so a later test that patches by dotted path patches something nobody uses (this made two
test_explain_vector endpoint tests fail whenever test_predictor.py ran first). No test may reload a production
module; tests change module state with monkeypatch, which pytest restores.
"""
import ast
from pathlib import Path

TESTS = Path(__file__).resolve().parent
PRODUCTION_PACKAGES = ("inference", "rl_engine", "session_ml", "utils", "capture", "evaluation", "training", "honeypot",
                       "windows_persona")


def _reloads(tree):
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            f = node.func
            name = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", "")
            if name == "reload":
                yield node


def test_no_test_reloads_a_production_module():
    offenders = []
    for path in sorted(TESTS.glob("test_*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for call in _reloads(tree):
            offenders.append(f"{path.name}:{call.lineno}")
    assert offenders == [], f"importlib.reload in tests breaks isolation: {offenders}"


def test_the_engine_and_the_predictor_module_share_one_class():
    """After every test module has been collected and imported, inference.main must still use the class that
    inference.predictor exposes (a reload would make these two objects differ)."""
    import inference.predictor as pred_mod
    import inference.main as main  # noqa: F401  (imported by other tests too)
    if getattr(main, "predictor", None) is not None:
        assert isinstance(main.predictor, pred_mod.SentinelPredictor)
    assert pred_mod.SentinelPredictor.__module__ == "inference.predictor"
