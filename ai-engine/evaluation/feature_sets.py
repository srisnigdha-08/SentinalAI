"""
Feature variants for development experiments (audit/ML_DEV_PROTOCOL.md §3). Each variant is a pure, stateless
function of the 53-column matrix in utils.features.FEATURE_NAMES order, so it cannot leak information between
splits and needs no fitting. The deployed 53-feature inference contract is unchanged; a candidate that wins would
apply the same function inside its pipeline.

A  baseline: the 53 features as served
B  A minus the 6 features that are constant in the CICIDS2017 pool (no information; time-of-day are dataset identity)
C  B minus init_win_bytes_forward/backward (TCP initial window = OS/tool fingerprint; KS 0.87-1.00 across tools)
D  A with log1p on timing, rate and volume features. NOTE: monotone per-feature transforms do not change the splits
   of tree models (XGBoost/RF) beyond histogram binning; D is a hypothesis about the Isolation Forest, whose random
   split points are drawn uniformly over each feature's range.
E  C + D + header length per packet (fwd/bwd_header_len divided by packet counts: a ratio, not monotone, so it does
   change what trees can see) — the Phase 8 "Schema F" idea on the served feature set.
"""
import numpy as np

from utils.features import FEATURE_NAMES

IDX = {n: i for i, n in enumerate(FEATURE_NAMES)}
CONSTANT_IN_POOL = ("bwd_psh_flags", "bwd_urg_flags", "fwd_avg_bytes_per_bulk", "bwd_avg_bytes_per_bulk",
                    "time_of_day_sin", "time_of_day_cos")  # experiments/shift_analysis_20261102/shift.json
TESTBED_IDENTITY = ("init_win_bytes_forward", "init_win_bytes_backward")
LOG_FEATURES = tuple(n for n in FEATURE_NAMES if "iat" in n or n in (
    "flow_duration", "flow_bytes_per_sec", "flow_packets_per_sec", "total_len_fwd_packets", "total_len_bwd_packets",
    "active_mean", "active_std", "idle_mean", "idle_std"))


def _drop(X, names, drop):
    keep = [i for i, n in enumerate(names) if n not in drop]
    return X[:, keep], [names[i] for i in keep]


def _log(X, names):
    X = X.astype(float, copy=True)
    for i, n in enumerate(names):
        if n in LOG_FEATURES:
            X[:, i] = np.log1p(np.maximum(X[:, i], 0.0))  # negative CICFlowMeter overflow artefacts -> 0
    return X


def _header_per_packet(X, names):
    X = X.astype(float, copy=True)
    pos = {n: i for i, n in enumerate(names)}
    for hdr, cnt in (("fwd_header_len", "total_fwd_packets"), ("bwd_header_len", "total_bwd_packets")):
        X[:, pos[hdr]] = X[:, pos[hdr]] / np.maximum(X[:, pos[cnt]], 1.0)
    return X


def variant(X, name: str):
    """(X', feature_names') for variant A-E. X must have the 53 columns in FEATURE_NAMES order."""
    X = np.asarray(X)
    if X.shape[1] != len(FEATURE_NAMES):
        raise ValueError(f"expected {len(FEATURE_NAMES)} columns, got {X.shape[1]}")
    names = list(FEATURE_NAMES)
    if name == "A":
        return X.astype(float, copy=True), names
    if name == "B":
        return _drop(X, names, CONSTANT_IN_POOL)
    if name == "C":
        return _drop(X, names, CONSTANT_IN_POOL + TESTBED_IDENTITY)
    if name == "D":
        return _log(X, names), names
    if name == "E":
        Xc, nc = _drop(X, names, CONSTANT_IN_POOL + TESTBED_IDENTITY)
        return _header_per_packet(_log(Xc, nc), nc), nc
    raise KeyError(f"unknown feature variant {name!r}")


VARIANTS = ("A", "B", "C", "D", "E")
