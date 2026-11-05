import json, os, sys
from pathlib import Path

# Add parent directory of inference to sys.path (so it can import from rl_engine)
sys.path.insert(0, str(Path(__file__).parent.parent))

from rl_engine.deception_scorer import (
    SessionScorer,
    is_test_or_diagnostic_mode,
    is_repo_runtime_write_authorized,
    get_default_runtime_path,
)

_scorer = None
DEFAULT_RUNTIME_Q_TABLE_PATH = str(Path(__file__).parent.parent / "runtime" / "q_table.json")

def get_scorer():
    global _scorer
    if _scorer is None:
        engine_root = Path(__file__).resolve().parent.parent
        model_dir = Path(os.getenv("MODEL_DIR") or engine_root / "models")
        model_dir = str(model_dir if model_dir.is_absolute() else engine_root / model_dir)
        repo_default_path = str(Path(__file__).parent.parent / "runtime" / "q_table.json")

        # Resolve the effective default runtime path:
        # 1. Environment variable override
        # 2. Monkeypatched module attribute (if modified by a test)
        # 3. get_default_runtime_path() which handles default-deny and PID isolation
        if "DEFAULT_RUNTIME_Q_TABLE_PATH" in os.environ:
            default_q_table = os.environ["DEFAULT_RUNTIME_Q_TABLE_PATH"]
        elif DEFAULT_RUNTIME_Q_TABLE_PATH != repo_default_path:
            default_q_table = DEFAULT_RUNTIME_Q_TABLE_PATH
        else:
            default_q_table = str(get_default_runtime_path())

        q_table_path = os.getenv("Q_TABLE_PATH", default_q_table)

        target = Path(q_table_path).resolve()
        models_dir = Path(model_dir).resolve()
        seed = (models_dir / "q_table.json").resolve()
        repo_runtime_dir = (Path(__file__).parent.parent / "runtime").resolve()
        repo_runtime_file = (repo_runtime_dir / "q_table.json").resolve()

        target_norm = os.path.normcase(str(target))
        seed_norm = os.path.normcase(str(seed))
        models_dir_norm = os.path.normcase(str(models_dir))
        runtime_dir_norm = os.path.normcase(str(repo_runtime_dir))
        runtime_file_norm = os.path.normcase(str(repo_runtime_file))

        is_seed_target = (target_norm == seed_norm or 
                          target_norm.startswith(models_dir_norm + os.sep) or 
                          target == seed)

        if is_seed_target:
            if is_test_or_diagnostic_mode() and os.getenv("SENTINEL_FAIL_CLOSED_ON_REPO_MUTATION", "").lower() in ("1", "true", "yes"):
                raise PermissionError(f"Scorer initialization targeting protected models directory ({target}) blocked.")
            q_table_path = default_q_table
            target = Path(q_table_path).resolve()
            target_norm = os.path.normcase(str(target))

        is_repo_runtime_target = (target_norm == runtime_file_norm or 
                                  target_norm.startswith(runtime_dir_norm + os.sep) or 
                                  target == repo_runtime_file)

        if is_repo_runtime_target and not is_repo_runtime_write_authorized():
            if is_test_or_diagnostic_mode() and os.getenv("SENTINEL_FAIL_CLOSED_ON_REPO_MUTATION", "").lower() in ("1", "true", "yes"):
                raise PermissionError(f"Scorer initialization targeting repository runtime ({target}) blocked under test/diagnostic mode.")
            elif is_test_or_diagnostic_mode():
                target = get_default_runtime_path()
                q_table_path = str(target)
            else:
                raise PermissionError(
                    f"Scorer initialization targeting repository runtime ({target}) rejected: "
                    "Repository persistence requires explicit authorization via SENTINEL_ALLOW_REPO_RUNTIME_WRITE=1."
                )

        # Stale temporary file eviction policy: if fresh runtime is explicitly requested,
        # unlink any existing temporary file so that it initializes cleanly from seed.
        is_isolated_temp = "sentinelai_isolated_runtime" in str(target)
        if is_isolated_temp and os.getenv("SENTINEL_FRESH_RUNTIME", "").lower() in ("1", "true", "yes"):
            if target.exists():
                try:
                    target.unlink()
                except OSError:
                    pass

        # Initialize separate writable state from the shipped learning artifact, stamped with where it came
        # from so learner stats can separate inherited episodes from sessions scored here. The seed is a
        # synthetic warm start; DECEPTION_COLD_START=1 starts from an empty table instead.
        # Existing runtime state and the original model file are never overwritten: exclusive creation ("x").
        cold_start = os.getenv("DECEPTION_COLD_START", "").lower() in ("1", "true", "yes")
        if not target.exists():
            initial = _initial_table(seed, cold_start)
            if initial is not None:
                target.parent.mkdir(parents=True, exist_ok=True)
                try:
                    with target.open("x", encoding="utf-8") as output:
                        json.dump(initial, output, indent=2)
                except FileExistsError:
                    pass
        _scorer = SessionScorer(q_table_path=q_table_path)
    return _scorer


def _initial_table(seed: Path, cold_start: bool):
    """Starting content for a new runtime Q-table, or None to let the learner start from defaults."""
    if cold_start:
        return {"q_table": {}, "episode_count": 0, "seed_provenance":
                {"source": "cold start (empty table)", "episodes": 0, "synthetic": False}}
    if not seed.is_file():
        return None
    try:
        data = json.loads(seed.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    data["seed_provenance"] = {"source": "models/q_table.json (synthetic warm start)",
                               "episodes": int(data.get("episode_count", 0)), "synthetic": True}
    return data


def save_scorer():
    """Flush only an initialized learner; prediction-only runs never mutate artifacts."""
    if _scorer is not None:
        _scorer.learner.save()
        return True
    return False
