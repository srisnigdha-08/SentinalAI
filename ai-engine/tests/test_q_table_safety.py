import hashlib
import os
from pathlib import Path
import pytest
from rl_engine.deception_scorer import DeceptionQLearner
from inference.deception import get_scorer

BASELINE_HASH = "bf9b46a1d1cf1b283797a544e7e597900b4a042e6c87ac199a3cc709498990ff"

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
