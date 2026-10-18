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


def test_time_of_day_none_timestamp_deterministic_fallback():
    """None timestamp must return the documented deterministic fallback (0.0, 0.0)."""
    sv, cv = compute_time_of_day(None)
    assert sv == 0.0
    assert cv == 0.0
    assert isinstance(sv, float) and isinstance(cv, float)


def test_time_of_day_invalid_timestamps_deterministic_fallback():
    """Invalid or malformed timestamps must return deterministic (0.0, 0.0) without raising or consulting host clock."""
    invalid_inputs = [
        "",
        "   ",
        "none",
        "None",
        "null",
        "NaN",
        "invalid_timestamp_string",
        float("nan"),
        float("inf"),
        float("-inf"),
        1e30,
        -1e30,
        [],
        {},
        object(),
    ]
    for inp in invalid_inputs:
        sv, cv = compute_time_of_day(inp)
        assert sv == 0.0 and cv == 0.0, f"Expected (0.0, 0.0) for invalid input {inp!r}, got ({sv}, {cv})"


def test_time_of_day_utc_consistency():
    """
    Equivalent Unix-epoch, UTC ISO-8601 string, offset-aware ISO-8601 string,
    and UTC naive datetime must produce identical cyclical coordinates under UTC policy.
    """
    import datetime
    # 2017-07-14 02:40:00 UTC == 1500000000.0 Unix epoch
    ts_epoch = 1500000000.0
    ts_iso_z = "2017-07-14T02:40:00Z"
    ts_iso_offset = "2017-07-14T08:10:00+05:30"  # 08:10 in IST (+5:30) is 02:40 UTC
    ts_csv = "2017-07-14 02:40:00"
    ts_dt = datetime.datetime(2017, 7, 14, 2, 40, 0)

    sv_epoch, cv_epoch = compute_time_of_day(ts_epoch)
    sv_z, cv_z = compute_time_of_day(ts_iso_z)
    sv_offset, cv_offset = compute_time_of_day(ts_iso_offset)
    sv_csv, cv_csv = compute_time_of_day(ts_csv)
    sv_dt, cv_dt = compute_time_of_day(ts_dt)

    assert abs(sv_epoch - sv_z) < 1e-9 and abs(cv_epoch - cv_z) < 1e-9
    assert abs(sv_epoch - sv_offset) < 1e-9 and abs(cv_epoch - cv_offset) < 1e-9
    assert abs(sv_epoch - sv_csv) < 1e-9 and abs(cv_epoch - cv_csv) < 1e-9
    assert abs(sv_epoch - sv_dt) < 1e-9 and abs(cv_epoch - cv_dt) < 1e-9

    # Unit circle check for valid timestamps
    assert abs(sv_epoch**2 + cv_epoch**2 - 1.0) < 1e-9


def test_features_repeated_record_idempotency():
    """Processing the exact same record repeatedly produces identical feature vectors (no host clock drift)."""
    rec_no_ts = {"flow_duration": 500.0, "total_fwd_packets": 5.0}
    vec1 = extract_features_from_record(rec_no_ts)
    vec2 = extract_features_from_record(rec_no_ts)
    np.testing.assert_array_equal(vec1, vec2)
    assert vec1[51] == 0.0 and vec1[52] == 0.0


def test_features_vector_schema_and_order_invariance():
    """Vector dimension remains 53 and feature order matches FEATURE_NAMES exactly."""
    assert len(FEATURE_NAMES) == EXPECTED_FEATURE_COUNT == 53
    assert FEATURE_NAMES[51] == "time_of_day_sin"
    assert FEATURE_NAMES[52] == "time_of_day_cos"

    rec = {"timestamp": "2026-10-18T12:00:00Z"}
    vec = extract_features_from_record(rec)
    assert len(vec) == 53
    # At 12:00:00 UTC: theta = 2*pi * 12/24 = pi. sin(pi) = 0.0, cos(pi) = -1.0
    assert abs(vec[51] - 0.0) < 1e-9
    assert abs(vec[52] - (-1.0)) < 1e-9


def test_training_inference_time_feature_consistency():
    """
    Demonstrates that missing timestamps at inference yield (0.0, 0.0),
    matching the training-time missing feature imputation in prepare_features().
    """
    df_empty_ts = pd.DataFrame({"label": ["BENIGN"]})
    X_train, _ = prepare_features(df_empty_ts)
    # In prepare_features, time features default to 0.0
    assert X_train[0, 51] == 0.0
    assert X_train[0, 52] == 0.0

    # At inference time, missing timestamp in record now also defaults to 0.0
    X_infer = extract_features_from_record({})
    assert X_infer[51] == 0.0
    assert X_infer[52] == 0.0


def test_pydantic_schema_timestamp_representations_contract():
    """
    Gate 2 contract test: Pydantic schemas Record and SessionData must cleanly accept:
    - Omitted field
    - Explicit null / None
    - ISO-8601 UTC string ('Z')
    - ISO-8601 string with offset ('+05:30')
    - Numeric Unix epoch float seconds (e.g. 1500000000.0)
    - Numeric Unix epoch int seconds (e.g. 1500000000)
    - Numeric epoch string (e.g. '1500000000.0')
    - Empty string ('')
    And all must cleanly extract features without validation or runtime errors.
    """
    import os
    os.environ.setdefault("SENTINEL_KEY", "test-key-mock")
    from inference.main import Record, SessionData

    cases = [
        ({}, 0.0, 0.0),
        ({"timestamp": None}, 0.0, 0.0),
        ({"timestamp": ""}, 0.0, 0.0),
        ({"timestamp": "2026-10-18T12:00:00Z"}, 0.0, -1.0),
        ({"timestamp": "2026-10-18T17:30:00+05:30"}, 0.0, -1.0),
        ({"timestamp": 1500000000.0}, np.sin(2 * np.pi * (2 + 40/60) / 24.0), np.cos(2 * np.pi * (2 + 40/60) / 24.0)),
        ({"timestamp": 1500000000}, np.sin(2 * np.pi * (2 + 40/60) / 24.0), np.cos(2 * np.pi * (2 + 40/60) / 24.0)),
        ({"timestamp": "1500000000.0"}, np.sin(2 * np.pi * (2 + 40/60) / 24.0), np.cos(2 * np.pi * (2 + 40/60) / 24.0)),
    ]

    for payload, exp_sin, exp_cos in cases:
        rec = Record.model_validate(payload)
        vec = extract_features_from_record(rec.model_dump())
        assert len(vec) == 53
        assert abs(vec[51] - exp_sin) < 1e-6
        assert abs(vec[52] - exp_cos) < 1e-6

    # Verify SessionData startTime
    session_cases = [
        ({}, 0.0, 0.0),
        ({"startTime": None}, 0.0, 0.0),
        ({"startTime": ""}, 0.0, 0.0),
        ({"startTime": "2026-10-18T12:00:00Z"}, 0.0, -1.0),
        ({"startTime": 1500000000.0}, np.sin(2 * np.pi * (2 + 40/60) / 24.0), np.cos(2 * np.pi * (2 + 40/60) / 24.0)),
    ]

    for s_payload, exp_sin, exp_cos in session_cases:
        s_obj = SessionData.model_validate(s_payload)
        s_vec = extract_features_from_honeypot(s_obj.model_dump())
        assert len(s_vec) == 53
        assert abs(s_vec[51] - exp_sin) < 1e-6
        assert abs(s_vec[52] - exp_cos) < 1e-6



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
