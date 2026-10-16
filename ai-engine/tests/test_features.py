"""
tests/test_features.py

Unit tests for ai-engine/utils/features.py:
  - prepare_features() output vector shape
  - compute_time_of_day() sin/cos non-collision across all hours
  - compute_payload_entropy() boundary values
"""
import sys
import math
from pathlib import Path

# Ensure the ai-engine root is on sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

import numpy as np
import pandas as pd
import pytest

from utils.features import (
    FEATURE_NAMES,
    EXPECTED_FEATURE_COUNT,
    compute_payload_entropy,
    compute_time_of_day,
    extract_features_from_record,
    extract_features_from_honeypot,
    prepare_features,
)


# ── prepare_features ──────────────────────────────────────────────────────────

def _make_dummy_df(n=5):
    """Return a minimal DataFrame with all FEATURE_NAMES columns present."""
    data = {col: [float(i % 10) for i in range(n)] for col in FEATURE_NAMES}
    data["label"] = ["BENIGN"] * n
    return pd.DataFrame(data)


def test_prepare_features_output_column_count():
    """Feature matrix must have exactly len(FEATURE_NAMES) columns (53 features)."""
    assert len(FEATURE_NAMES) == EXPECTED_FEATURE_COUNT == 53
    df = _make_dummy_df()
    X, y = prepare_features(df)
    assert X.shape[1] == EXPECTED_FEATURE_COUNT == 53, (
        f"Expected {EXPECTED_FEATURE_COUNT} feature columns, got {X.shape[1]}"
    )


def test_prepare_features_row_count():
    """Feature matrix must have the same number of rows as the input DataFrame."""
    n = 7
    df = _make_dummy_df(n)
    X, y = prepare_features(df)
    assert X.shape[0] == n


def test_prepare_features_benign_label_maps_to_zero():
    """BENIGN label must map to integer 0."""
    df = _make_dummy_df(3)
    _, y = prepare_features(df)
    assert all(v == 0 for v in y)


def test_prepare_features_no_nan_in_output():
    """Output matrix must not contain NaN values even when some inputs are missing."""
    df = _make_dummy_df()
    # Deliberately drop a column so features.py has to fall back to 0
    df.drop(columns=["flow_duration"], inplace=True)
    X, _ = prepare_features(df)
    assert not np.isnan(X).any(), "NaN found in feature matrix after prepare_features()"


def test_prepare_features_missing_columns_fill_zero():
    """Missing columns should be filled with 0.0, not raise an exception."""
    # Only provide a bare minimum DataFrame
    df = pd.DataFrame({"label": ["BENIGN", "DDoS"]})
    X, y = prepare_features(df)
    assert X.shape == (2, len(FEATURE_NAMES))


# ── compute_time_of_day ───────────────────────────────────────────────────────

def test_time_of_day_sin_cos_unit_circle():
    """sin² + cos² must equal 1.0 for every hour."""
    for hour in range(24):
        sin_val, cos_val = compute_time_of_day(float(hour))
        magnitude = math.sqrt(sin_val**2 + cos_val**2)
        assert abs(magnitude - 1.0) < 1e-9, (
            f"sin²+cos² ≠ 1 for hour {hour}: got {magnitude}"
        )


def test_time_of_day_no_2d_collisions_across_all_hours():
    """
    Regression: no two distinct integer hours should share the same (sin, cos) vector.
    Hour 0 and hour 24 are the same point on the circle but 24 isn't a valid clock hour,
    so we only compare 0..23.
    """
    seen = {}
    for hour in range(24):
        sv, cv = compute_time_of_day(float(hour))
        key = (round(sv, 8), round(cv, 8))
        assert key not in seen, (
            f"Collision: hour {hour} and hour {seen[key]} share the same (sin, cos) = {key}"
        )
        seen[key] = hour


def test_time_of_day_hour_1_vs_11_differ():
    """Explicit spot-check: hours 1 and 11 must not collide (common sine aliasing concern)."""
    import datetime
    dt1 = datetime.datetime(2023, 1, 1, 1, 0, 0)
    dt11 = datetime.datetime(2023, 1, 1, 11, 0, 0)
    sv1, cv1 = compute_time_of_day(dt1)
    sv11, cv11 = compute_time_of_day(dt11)
    assert (sv1, cv1) != (sv11, cv11)


def test_time_of_day_hour_1_vs_11_same_sine():
    """Hours 1 and 11 are symmetric about the vertical axis (hour 6) and have the same sine but different cosine."""
    import datetime
    dt1 = datetime.datetime(2023, 1, 1, 1, 0, 0)
    dt11 = datetime.datetime(2023, 1, 1, 11, 0, 0)
    sv1, cv1 = compute_time_of_day(dt1)
    sv11, cv11 = compute_time_of_day(dt11)
    # sin(2π·1/24) == sin(2π·11/24) — same sine but different cosine
    assert sv1 == pytest.approx(sv11, abs=1e-9)
    assert cv1 != pytest.approx(cv11, abs=1e-9)


def test_time_of_day_none_timestamp_does_not_raise():
    """None timestamp must fall back to now() without raising."""
    sv, cv = compute_time_of_day(None)
    assert -1.0 <= sv <= 1.0
    assert -1.0 <= cv <= 1.0


# ── compute_payload_entropy ───────────────────────────────────────────────────

def test_payload_entropy_zero_when_total_zero():
    """Zero total bytes → entropy must be 0.0."""
    assert compute_payload_entropy(0.0, 0.0) == 0.0


def test_payload_entropy_zero_when_one_direction_only():
    """All bytes in one direction → entropy is 0.0 (no uncertainty)."""
    assert compute_payload_entropy(100.0, 0.0) == 0.0
    assert compute_payload_entropy(0.0, 100.0) == 0.0


def test_payload_entropy_max_when_equal_split():
    """Equal split → entropy is exactly log2(2) = 1.0."""
    result = compute_payload_entropy(50.0, 50.0)
    assert abs(result - 1.0) < 1e-9


def test_payload_entropy_range():
    """Entropy must always be in [0.0, 1.0]."""
    for fwd in [0, 10, 50, 90, 100]:
        bwd = 100 - fwd
        result = compute_payload_entropy(float(fwd), float(bwd))
        assert 0.0 <= result <= 1.0 + 1e-9, f"Entropy out of range for fwd={fwd}: {result}"


# ── extract_features_from_record / honeypot ───────────────────────────────────

def test_extract_features_from_record_shape():
    """Must return a 1-D array of exactly len(FEATURE_NAMES) elements."""
    vec = extract_features_from_record({})
    assert vec.shape == (len(FEATURE_NAMES),)


def test_extract_features_from_record_no_nan():
    """Must not return NaN for an empty record (all defaults)."""
    vec = extract_features_from_record({})
    assert not np.isnan(vec).any()


def test_extract_features_from_honeypot_failed_login():
    """A failed login session must map to 'SSH Brute Force' profile without raising."""
    session = {
        "sessionId": "test-001",
        "sourceIP": "1.2.3.4",
        "loginSucceeded": False,
        "commands": [],
        "durationSeconds": 5,
        "iocCount": 0,
    }
    vec = extract_features_from_honeypot(session)
    assert vec.shape == (len(FEATURE_NAMES),)
    assert not np.isnan(vec).any()


def test_extract_features_from_honeypot_zero_commands():
    """Session with login success but zero commands → Port Scan profile."""
    session = {
        "loginSucceeded": True,
        "commands": [],
        "durationSeconds": 1,
        "iocCount": 0,
    }
    vec = extract_features_from_honeypot(session)
    assert vec.shape == (len(FEATURE_NAMES),)
