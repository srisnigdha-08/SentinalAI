import hashlib
import json
import os
from pathlib import Path
import pytest
from rl_engine.deception_scorer import DeceptionQLearner
from inference.deception import get_scorer

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
