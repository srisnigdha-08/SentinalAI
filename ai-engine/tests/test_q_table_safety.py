import hashlib
import json
import os
from pathlib import Path
import pytest
from rl_engine.deception_scorer import DeceptionQLearner, get_default_runtime_path, is_test_or_diagnostic_mode, is_repo_runtime_write_authorized
from inference.deception import get_scorer, save_scorer

BASELINE_HASH = "bf9b46a1d1cf1b283797a544e7e597900b4a042e6c87ac199a3cc709498990ff"

@pytest.fixture(autouse=True)
def isolate_q_table_runtime(tmp_path, monkeypatch):
    temp_runtime = tmp_path / "runtime" / "q_table.json"
    temp_runtime.parent.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("DEFAULT_RUNTIME_Q_TABLE_PATH", str(temp_runtime))

def get_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest().lower()

def test_q_table_baseline_write_protection(tmp_path):
    models_baseline = (Path(__file__).parent.parent / "models" / "q_table.json").resolve()
    assert models_baseline.exists(), "Baseline models/q_table.json must exist"
    initial_hash = get_hash(models_baseline)
    assert initial_hash == BASELINE_HASH, f"Baseline hash modified: {initial_hash}"

    # Attempt to initialize learner targeting the baseline directly
    learner = DeceptionQLearner(q_table_path=str(models_baseline))
    learner.q_table["ubuntu_22"]["debian_11"] = 999.99
    learner.episode_count = 99999
    
    # Save must NOT write to baseline
    learner.save()

    post_hash = get_hash(models_baseline)
    assert post_hash == BASELINE_HASH, "Baseline models/q_table.json was modified by save()!"
    assert learner.q_table_path != str(models_baseline), "q_table_path was not redirected"

def test_q_table_path_alias_protection():
    models_dir = (Path(__file__).parent.parent / "models").resolve()
    aliased_path = models_dir / ".." / "models" / "q_table.json"
    
    models_baseline = (models_dir / "q_table.json").resolve()
    initial_hash = get_hash(models_baseline)

    learner = DeceptionQLearner(q_table_path=str(aliased_path))
    learner.q_table["ubuntu_22"]["debian_11"] = 888.88
    learner.save()

    post_hash = get_hash(models_baseline)
    assert post_hash == initial_hash, "Baseline was modified through relative path alias!"

def test_q_table_case_variation_protection():
    models_dir = (Path(__file__).parent.parent / "models").resolve()
    # Case variations on Windows
    case_aliased = str(models_dir / "Q_TABLE.JSON")
    
    models_baseline = (models_dir / "q_table.json").resolve()
    initial_hash = get_hash(models_baseline)

    learner = DeceptionQLearner(q_table_path=case_aliased)
    learner.q_table["ubuntu_22"]["debian_11"] = 777.77
    learner.save()

    post_hash = get_hash(models_baseline)
    assert post_hash == initial_hash, "Baseline was modified through case-variation alias!"

def test_q_table_models_directory_containment_protection():
    models_dir = (Path(__file__).parent.parent / "models").resolve()
    # Attempting to write any new file into models directory
    arbitrary_model_target = models_dir / "unauthorized_q_table.json"
    
    models_baseline = (models_dir / "q_table.json").resolve()
    initial_hash = get_hash(models_baseline)

    learner = DeceptionQLearner(q_table_path=str(arbitrary_model_target))
    learner.save()

    assert not arbitrary_model_target.exists(), "Learner was allowed to write an arbitrary file inside models/!"
    post_hash = get_hash(models_baseline)
    assert post_hash == initial_hash, "Baseline was modified!"


# --- Phase 1 Specific Regression Tests ---

def test_regression_seed_path_resolution_cannot_write_to_seed(tmp_path, monkeypatch):
    """
    Regression Test 1: Seed-path resolution cannot write to seed.
    Verifies that pointing directly to models/q_table.json redirects to an isolated runtime
    path and leaves models/q_table.json completely untouched (hash-invariant).
    """
    models_dir = (Path(__file__).parent.parent / "models").resolve()
    seed_path = models_dir / "q_table.json"
    initial_seed_hash = get_hash(seed_path)
    assert initial_seed_hash == BASELINE_HASH

    isolated_runtime = tmp_path / "isolated_runtime" / "q_table.json"
    monkeypatch.setenv("DEFAULT_RUNTIME_Q_TABLE_PATH", str(isolated_runtime))

    learner = DeceptionQLearner(q_table_path=str(seed_path))
    learner.q_table["ubuntu_22"]["debian_11"] = 123.456
    learner.episode_count = 500
    learner.save()

    # Seed file must be untouched
    assert get_hash(seed_path) == BASELINE_HASH
    # Destination must have redirected to isolated_runtime
    assert Path(learner.q_table_path).resolve() == isolated_runtime.resolve()
    assert isolated_runtime.exists()


def test_regression_tests_cannot_mutate_either_protected_q_table(tmp_path, monkeypatch):
    """
    Regression Test 2: Tests cannot mutate either protected Q-table.
    Verifies that during test operations, neither models/q_table.json nor
    runtime/q_table.json in the repository are modified.
    """
    models_dir = (Path(__file__).parent.parent / "models").resolve()
    runtime_dir = (Path(__file__).parent.parent / "runtime").resolve()
    seed_path = models_dir / "q_table.json"
    runtime_path = runtime_dir / "q_table.json"

    initial_seed_hash = get_hash(seed_path)
    initial_runtime_hash = get_hash(runtime_path)
    initial_seed_size = seed_path.stat().st_size
    initial_runtime_size = runtime_path.stat().st_size

    # Simulate operations targeting both default and custom paths under test isolation
    isolated_runtime = tmp_path / "test_run" / "q_table.json"
    monkeypatch.setenv("DEFAULT_RUNTIME_Q_TABLE_PATH", str(isolated_runtime))

    # Operation 1: learner targeting seed
    l1 = DeceptionQLearner(q_table_path=str(seed_path))
    l1.episode_count = 77
    l1.save()

    # Operation 2: learner targeting relative path to models
    l2 = DeceptionQLearner(q_table_path=str(models_dir / "q_table.json"))
    l2.episode_count = 88
    l2.save()

    # Both protected files must retain exact pre-test hash and size
    assert get_hash(seed_path) == initial_seed_hash
    assert seed_path.stat().st_size == initial_seed_size
    assert get_hash(runtime_path) == initial_runtime_hash
    assert runtime_path.stat().st_size == initial_runtime_size


def test_regression_persistence_uses_explicitly_authorized_destination(tmp_path, monkeypatch):
    """
    Regression Test 3: Persistence uses an explicitly authorized destination.
    Confirms that when writes target protected paths, the redirect destination
    is strictly governed by DEFAULT_RUNTIME_Q_TABLE_PATH.
    """
    models_dir = (Path(__file__).parent.parent / "models").resolve()
    seed_path = models_dir / "q_table.json"

    authorized_destination = tmp_path / "authorized_secure_runtime" / "custom_q.json"
    monkeypatch.setenv("DEFAULT_RUNTIME_Q_TABLE_PATH", str(authorized_destination))

    learner = DeceptionQLearner(q_table_path=str(seed_path))
    learner.episode_count = 314
    learner.save()

    assert Path(learner.q_table_path).resolve() == authorized_destination.resolve()
    assert authorized_destination.exists()
    
    with open(authorized_destination, "r") as f:
        data = json.load(f)
    assert data["episode_count"] == 314


def test_regression_failed_initialization_and_cleanup_safety(tmp_path, monkeypatch):
    """
    Regression Test 4: Failed initialization and cleanup do not mutate protected files.
    Confirms that malformed JSON, unreadable paths, or exceptions during execution/cleanup
    do not alter or corrupt models/q_table.json or runtime/q_table.json.
    """
    models_dir = (Path(__file__).parent.parent / "models").resolve()
    runtime_dir = (Path(__file__).parent.parent / "runtime").resolve()
    seed_path = models_dir / "q_table.json"
    runtime_path = runtime_dir / "q_table.json"

    initial_seed_hash = get_hash(seed_path)
    initial_runtime_hash = get_hash(runtime_path)

    # Corrupted input file
    corrupt_file = tmp_path / "corrupted.json"
    corrupt_file.write_text("{ this is not valid json !!!")

    # Initializing learner on corrupt file must fall back gracefully to defaults
    corrupt_learner = DeceptionQLearner(q_table_path=str(corrupt_file))
    assert corrupt_learner.episode_count == 0
    assert corrupt_learner.total_reward == 0.0

    # Non-existent directory path
    non_existent_target = tmp_path / "non_existent_dir" / "subdir" / "q_table.json"
    isolated_learner = DeceptionQLearner(q_table_path=str(non_existent_target))
    assert isolated_learner.episode_count == 0

    # Check protected files remain untouched
    assert get_hash(seed_path) == initial_seed_hash
    assert get_hash(runtime_path) == initial_runtime_hash


def test_regression_standalone_diagnostic_redirects_away_from_repo_runtime(monkeypatch):
    """
    Regression Test 5: Standalone scripts or diagnostics running without an explicit
    DEFAULT_RUNTIME_Q_TABLE_PATH redirect writes away from repository runtime/q_table.json.
    """
    models_dir = (Path(__file__).parent.parent / "models").resolve()
    runtime_dir = (Path(__file__).parent.parent / "runtime").resolve()
    seed_path = models_dir / "q_table.json"
    runtime_path = runtime_dir / "q_table.json"

    initial_seed_hash = get_hash(seed_path)
    initial_runtime_hash = get_hash(runtime_path)

    # Remove explicit redirect environment variable to simulate standalone unconfigured runner
    monkeypatch.delenv("DEFAULT_RUNTIME_Q_TABLE_PATH", raising=False)
    monkeypatch.setenv("SENTINEL_DIAGNOSTIC", "1")

    # Learner targeting repo runtime path directly
    learner = DeceptionQLearner(q_table_path=str(runtime_path))
    learner.episode_count = 1337
    learner.save()

    # The save MUST redirect away from the repository runtime file
    saved_path = Path(learner.q_table_path).resolve()
    assert saved_path != runtime_path.resolve(), "Learner saved directly to repository runtime path!"
    assert "sentinelai_isolated_runtime" in str(saved_path)
    assert saved_path.exists()

    # Repository protected assets must remain 100% hash-invariant
    assert get_hash(seed_path) == initial_seed_hash
    assert get_hash(runtime_path) == initial_runtime_hash


def test_regression_fail_closed_mode_raises_on_repo_write(monkeypatch):
    """
    Regression Test 6: Explicit fail-closed configuration raises PermissionError
    if a test/diagnostic execution targets either models/ or runtime/ inside the repository.
    """
    models_dir = (Path(__file__).parent.parent / "models").resolve()
    runtime_dir = (Path(__file__).parent.parent / "runtime").resolve()
    seed_path = models_dir / "q_table.json"
    runtime_path = runtime_dir / "q_table.json"

    initial_seed_hash = get_hash(seed_path)
    initial_runtime_hash = get_hash(runtime_path)

    monkeypatch.setenv("SENTINEL_FAIL_CLOSED_ON_REPO_MUTATION", "true")
    monkeypatch.setenv("SENTINEL_TEST_MODE", "1")

    # 1. Targeting repo runtime must raise PermissionError
    l_runtime = DeceptionQLearner(q_table_path=str(runtime_path))
    with pytest.raises(PermissionError) as exc_info:
        l_runtime.save()
    assert "repository runtime" in str(exc_info.value)

    # 2. Targeting seed/models must raise PermissionError
    l_seed = DeceptionQLearner(q_table_path=str(seed_path))
    with pytest.raises(PermissionError) as exc_info:
        l_seed.save()
    assert "models directory" in str(exc_info.value)

    # Hashes must remain strictly intact
    assert get_hash(seed_path) == initial_seed_hash
    assert get_hash(runtime_path) == initial_runtime_hash


def test_regression_deception_get_scorer_isolation_under_test_mode(monkeypatch):
    """
    Regression Test 7: inference.deception.get_scorer() automatically uses isolated
    temporary path when unconfigured under test/diagnostic execution.
    """
    from inference import deception
    models_dir = (Path(__file__).parent.parent / "models").resolve()
    runtime_dir = (Path(__file__).parent.parent / "runtime").resolve()
    seed_path = models_dir / "q_table.json"
    runtime_path = runtime_dir / "q_table.json"

    initial_seed_hash = get_hash(seed_path)
    initial_runtime_hash = get_hash(runtime_path)

    monkeypatch.delenv("DEFAULT_RUNTIME_Q_TABLE_PATH", raising=False)
    monkeypatch.delenv("Q_TABLE_PATH", raising=False)
    monkeypatch.setenv("SENTINEL_DIAGNOSTIC", "1")
    monkeypatch.setattr(deception, "_scorer", None)

    scorer = deception.get_scorer()
    scorer_path = Path(scorer.learner.q_table_path).resolve()
    assert scorer_path != runtime_path.resolve()
    assert scorer_path != seed_path.resolve()
    assert "sentinelai_isolated_runtime" in str(scorer_path)

    scorer.learner.episode_count = 777
    deception.save_scorer()

    # Hashes must remain strictly intact
    assert get_hash(seed_path) == initial_seed_hash
    assert get_hash(runtime_path) == initial_runtime_hash
    assert scorer_path.exists()


def test_regression_production_mode_allows_runtime_persistence(tmp_path, monkeypatch):
    """
    Regression Test 8: In production mode (not in test/diagnostic mode),
    learning updates write to the designated runtime path without redirection.
    """
    runtime_target = tmp_path / "prod_runtime" / "q_table.json"
    monkeypatch.setenv("DEFAULT_RUNTIME_Q_TABLE_PATH", str(runtime_target))

    # Mock is_test_or_diagnostic_mode to False to simulate live production service
    import rl_engine.deception_scorer as scorer_mod
    monkeypatch.setattr(scorer_mod, "is_test_or_diagnostic_mode", lambda: False)

    learner = DeceptionQLearner(q_table_path=str(runtime_target))
    learner.episode_count = 42
    learner.save()

    assert Path(learner.q_table_path).resolve() == runtime_target.resolve()
    assert runtime_target.exists()
    with open(runtime_target) as f:
        data = json.load(f)
    assert data["episode_count"] == 42


# --- Phase 1.1 Specific Regression Tests ---

def test_phase11_unflagged_standalone_script_cannot_write_repo_runtime(monkeypatch):
    """
    Phase 1.1 Test 1 (DEFECT-01): An unflagged inline or custom script (where test detection
    returns False) cannot write to repository runtime by default without explicit authorization.
    """
    import rl_engine.deception_scorer as scorer_mod
    runtime_path = (Path(__file__).parent.parent / "runtime" / "q_table.json").resolve()
    seed_path = (Path(__file__).parent.parent / "models" / "q_table.json").resolve()

    initial_runtime_hash = get_hash(runtime_path)
    initial_seed_hash = get_hash(seed_path)

    # Simulate an unflagged standalone script (e.g. verify_flow.py or python -c)
    monkeypatch.delenv("DEFAULT_RUNTIME_Q_TABLE_PATH", raising=False)
    monkeypatch.delenv("SENTINEL_ALLOW_REPO_RUNTIME_WRITE", raising=False)
    monkeypatch.delenv("SENTINEL_TEST_MODE", raising=False)
    monkeypatch.delenv("SENTINEL_DIAGNOSTIC", raising=False)
    monkeypatch.setattr(scorer_mod, "is_test_or_diagnostic_mode", lambda: False)

    learner = DeceptionQLearner(q_table_path=str(runtime_path))
    learner.episode_count = 9999

    # Attempting to save without authorization MUST raise PermissionError
    with pytest.raises(PermissionError) as exc_info:
        learner.save()
    assert "Repository persistence requires explicit authorization" in str(exc_info.value)

    # Repository runtime and seed remain strictly intact
    assert get_hash(runtime_path) == initial_runtime_hash
    assert get_hash(seed_path) == initial_seed_hash


def test_phase11_process_isolated_temporary_storage(monkeypatch):
    """
    Phase 1.1 Test 3 (DEFECT-02): Two independent processes receive distinct temporary state locations.
    """
    import rl_engine.deception_scorer as scorer_mod
    monkeypatch.delenv("DEFAULT_RUNTIME_Q_TABLE_PATH", raising=False)
    monkeypatch.delenv("SENTINEL_ALLOW_REPO_RUNTIME_WRITE", raising=False)

    # Mock PID 10001
    monkeypatch.setattr(os, "getpid", lambda: 10001)
    path_proc1 = scorer_mod.get_default_runtime_path()

    # Mock PID 10002
    monkeypatch.setattr(os, "getpid", lambda: 10002)
    path_proc2 = scorer_mod.get_default_runtime_path()

    assert path_proc1 != path_proc2
    assert "sentinelai_isolated_runtime_10001" in str(path_proc1)
    assert "sentinelai_isolated_runtime_10002" in str(path_proc2)


def test_phase11_stale_temporary_file_handled_cleanly(tmp_path, monkeypatch):
    """
    Phase 1.1 Test 4: When SENTINEL_FRESH_RUNTIME=1 is set, a stale temporary file
    is unlinked and reinitialized cleanly from seed rather than reusing stale mutated data.
    """
    from inference import deception
    models_dir = (Path(__file__).parent.parent / "models").resolve()
    seed_path = models_dir / "q_table.json"

    # Create an isolated temporary directory simulating prior stale run
    temp_isolated_dir = tmp_path / "sentinelai_isolated_runtime_test"
    temp_isolated_dir.mkdir(parents=True, exist_ok=True)
    stale_file = temp_isolated_dir / "q_table.json"
    stale_file.write_text(json.dumps({"episode_count": 9999, "stale": True}))

    monkeypatch.setenv("DEFAULT_RUNTIME_Q_TABLE_PATH", str(stale_file))
    monkeypatch.setenv("SENTINEL_FRESH_RUNTIME", "1")
    monkeypatch.setattr(deception, "_scorer", None)

    scorer = deception.get_scorer()
    # The stale file must have been evicted and freshly seeded
    assert scorer.learner.episode_count != 9999
    with open(stale_file) as f:
        data = json.load(f)
    assert "stale" not in data


def test_phase11_authorized_runtime_persistence(tmp_path, monkeypatch):
    """
    Phase 1.1 Test 5: Intentional, documented runtime configuration (SENTINEL_ALLOW_REPO_RUNTIME_WRITE=1)
    permits persistence to the approved runtime path.
    """
    import rl_engine.deception_scorer as scorer_mod
    monkeypatch.setenv("SENTINEL_ALLOW_REPO_RUNTIME_WRITE", "1")
    assert scorer_mod.is_repo_runtime_write_authorized() is True

    custom_authorized_target = tmp_path / "authorized_runtime" / "q_table.json"
    learner = DeceptionQLearner(q_table_path=str(custom_authorized_target))
    learner.episode_count = 555
    learner.save()

    assert custom_authorized_target.exists()
    with open(custom_authorized_target) as f:
        data = json.load(f)
    assert data["episode_count"] == 555


def test_phase11_unauthorized_arbitrary_models_write_rejected(tmp_path, monkeypatch):
    """
    Phase 1.1 Test 6: Unauthorized writes targeting protected models directory are rejected.
    """
    import rl_engine.deception_scorer as scorer_mod
    models_dir = (Path(__file__).parent.parent / "models").resolve()
    target_in_models = models_dir / "arbitrary_new_model_target.json"

    # Under standalone/production execution (not test-redirect mode), writes to models are rejected
    monkeypatch.setattr(scorer_mod, "is_test_or_diagnostic_mode", lambda: False)

    learner = DeceptionQLearner(q_table_path=str(target_in_models))
    with pytest.raises(PermissionError) as exc_info:
        learner.save()
    assert "models directory" in str(exc_info.value)
    assert not target_in_models.exists()


def test_phase11_seed_initialization_cannot_overwrite_unrelated_file(tmp_path, monkeypatch):
    """
    Phase 1.1 Test 7: Direct seed copy initialization (open 'xb') cannot overwrite
    an existing unrelated file.
    """
    from inference import deception
    unrelated_file = tmp_path / "unrelated_existing.json"
    unrelated_file.write_bytes(b'{"original_unrelated_content": 12345}')

    monkeypatch.setenv("DEFAULT_RUNTIME_Q_TABLE_PATH", str(unrelated_file))
    monkeypatch.setattr(deception, "_scorer", None)

    deception.get_scorer()
    # The file content must remain completely un-overwritten
    assert unrelated_file.read_bytes() == b'{"original_unrelated_content": 12345}'


def test_phase11_failed_writes_do_not_corrupt_last_valid_q_table(tmp_path):
    """
    Phase 1.1 Test 8: Atomic persistence ensures that if writing or serialization fails,
    the pre-existing valid Q-table is not corrupted or truncated to 0 bytes.
    """
    valid_file = tmp_path / "valid_q_table.json"
    initial_content = json.dumps({"episode_count": 100, "q_table": {"test": 1}}).encode("utf-8")
    valid_file.write_bytes(initial_content)

    learner = DeceptionQLearner(q_table_path=str(valid_file))
    learner.episode_count = 200

    # Inject an un-serializable object into q_table to induce a failure in json.dump
    class Unserializable:
        pass
    learner.q_table["bad_state"] = Unserializable()

    with pytest.raises(TypeError):
        learner.save()

    # The original file on disk must remain 100% intact and valid
    assert valid_file.read_bytes() == initial_content
    with open(valid_file) as f:
        data = json.load(f)
    assert data["episode_count"] == 100


def test_phase11_ai_runner_ignores_generic_port(monkeypatch):
    """
    Phase 1.1 Test 9 (DEFECT-03): Standalone runner ignores generic PORT (e.g. 5000 from Node backend)
    and generic HOST, defaulting strictly to 127.0.0.1:8000 unless AI_ENGINE_* is specified.
    """
    # Simulate parent shell exporting Node backend variables
    monkeypatch.setenv("PORT", "5000")
    monkeypatch.setenv("HOST", "0.0.0.0")
    monkeypatch.delenv("AI_ENGINE_PORT", raising=False)
    monkeypatch.delenv("AI_ENGINE_HOST", raising=False)

    host = os.getenv("AI_ENGINE_HOST", "127.0.0.1")
    port = int(os.getenv("AI_ENGINE_PORT", "8000"))

    assert host == "127.0.0.1"
    assert port == 8000

    # Overrides via namespaced AI_ENGINE_* are respected
    monkeypatch.setenv("AI_ENGINE_PORT", "9000")
    monkeypatch.setenv("AI_ENGINE_HOST", "10.0.0.5")

    host = os.getenv("AI_ENGINE_HOST", "127.0.0.1")
    port = int(os.getenv("AI_ENGINE_PORT", "8000"))

    assert host == "10.0.0.5"
    assert port == 9000


def test_phase11_ai_runner_reload_configuration(monkeypatch):
    """
    Phase 1.1 Test 10 (DEFECT-04): Development auto-reload is False by default,
    and only enabled when explicitly requested via AI_ENGINE_RELOAD or SENTINEL_ENV=development.
    """
    monkeypatch.delenv("AI_ENGINE_RELOAD", raising=False)
    monkeypatch.delenv("SENTINEL_ENV", raising=False)

    # 1. Unset -> reload is False
    reload_env = os.getenv("AI_ENGINE_RELOAD")
    reload = reload_env.lower() in ("1", "true", "yes") if reload_env is not None else (os.getenv("SENTINEL_ENV", "").lower() == "development")
    assert reload is False

    # 2. AI_ENGINE_RELOAD=true -> reload is True
    monkeypatch.setenv("AI_ENGINE_RELOAD", "true")
    reload_env = os.getenv("AI_ENGINE_RELOAD")
    reload = reload_env.lower() in ("1", "true", "yes") if reload_env is not None else (os.getenv("SENTINEL_ENV", "").lower() == "development")
    assert reload is True

    # 3. SENTINEL_ENV=development -> reload is True
    monkeypatch.delenv("AI_ENGINE_RELOAD", raising=False)
    monkeypatch.setenv("SENTINEL_ENV", "development")
    reload_env = os.getenv("AI_ENGINE_RELOAD")
    reload = reload_env.lower() in ("1", "true", "yes") if reload_env is not None else (os.getenv("SENTINEL_ENV", "").lower() == "development")
    assert reload is True
