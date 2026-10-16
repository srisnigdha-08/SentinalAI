"""
SentinelAI Bounded Connection-State Interface & Memory Safety Management
Phase 9C.2 Remediation Milestone: DEF-03 Fix

================================================================================
CRITICAL ARCHITECTURAL WARNING:
Production memory caps and eviction parameters must NOT be selected or finalized
without empirical benchmark evidence on target workload traffic distributions.
Static hardcoded limits risk either memory exhaustion under volumetric floods
or premature state eviction under low-and-slow brute force campaigns.
All limits must be configurable and accompanied by benchmark review.
================================================================================
"""

from __future__ import annotations
import math
import time
import logging
import threading
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple, Union

log = logging.getLogger("sentinel.modular.state")


@dataclass
class StateMetrics:
    """Live telemetry on memory usage and eviction dynamics."""
    max_entries: int
    current_entries: int = 0
    total_record_calls: int = 0
    hits: int = 0
    misses: int = 0
    evictions: int = 0
    expired_purges: int = 0
    last_purge_timestamp: float = 0.0


@dataclass
class ConnectionStateEntry:
    """Represents stateful history for a single connection key."""
    key: Union[str, Tuple[Any, ...]]
    first_seen: float
    last_seen: float
    attempt_count: float
    decayed_score: float
    metadata: Dict[str, Any] = field(default_factory=dict)
    ttl_seconds: Optional[float] = None


def _validate_numeric_increment(increment: Any) -> float:
    """Strictly validates increment value prior to touching connection state."""
    if increment is None:
        raise ValueError("increment cannot be None")
    if isinstance(increment, bool) or not isinstance(increment, (int, float)):
        raise TypeError(f"increment must be a real number, got {type(increment).__name__}")
    val = float(increment)
    if not math.isfinite(val):
        raise ValueError(f"increment must be a finite number, got {val}")
    if val <= 0:
        raise ValueError(f"increment must be strictly positive (> 0), got {val}")
    return val


def _validate_timestamp(ts: Any, field_name: str = "current_time") -> float:
    """Validates timestamp values prior to state computation."""
    if ts is None:
        raise ValueError(f"{field_name} cannot be None")
    if isinstance(ts, bool) or not isinstance(ts, (int, float)):
        raise TypeError(f"{field_name} must be a real number, got {type(ts).__name__}")
    val = float(ts)
    if not math.isfinite(val) or val < 0:
        raise ValueError(f"{field_name} must be a non-negative finite number, got {val}")
    return val


class BoundedConnectionStateTable:
    """
    Thread-safe, bounded, in-memory state table with LRU eviction and exponential decay.
    
    Designed to support stateful threat detection (e.g., SSH/FTP brute force, port scans)
    without unbounded heap growth or memory bloat.
    
    Parameters:
    -----------
    max_entries: int
        Hard ceiling on the number of tracked connection keys. Default: 10,000.
        When table reaches capacity, the least-recently-used (LRU) entry is evicted.
    default_ttl_seconds: float
        Time-to-live after which an unvisited entry is eligible for expiration purge.
    decay_half_life_seconds: float
        Half-life lambda parameter for exponential decay scoring:
        score(t) = score(t0) * e^(-lambda * dt) + increment
    """

    def __init__(
        self,
        max_entries: int = 10000,
        default_ttl_seconds: float = 300.0,
        decay_half_life_seconds: float = 120.0,
    ):
        if max_entries <= 0:
            raise ValueError(f"max_entries must be a positive integer, got {max_entries}")
        if default_ttl_seconds <= 0:
            raise ValueError(f"default_ttl_seconds must be positive, got {default_ttl_seconds}")
        if decay_half_life_seconds <= 0:
            raise ValueError(f"decay_half_life_seconds must be positive, got {decay_half_life_seconds}")

        self.max_entries = max_entries
        self.default_ttl = default_ttl_seconds
        self.decay_lambda = math.log(2.0) / decay_half_life_seconds

        self._lock = threading.RLock()
        self._table: OrderedDict[Union[str, Tuple[Any, ...]], ConnectionStateEntry] = OrderedDict()
        self._metrics = StateMetrics(max_entries=self.max_entries)

    def record_attempt(
        self,
        key: Union[str, Tuple[Any, ...]],
        current_time: Optional[float] = None,
        increment: float = 1.0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ConnectionStateEntry:
        """
        Records an attempt for the given connection key, applying exponential decay to past history.
        Maintains LRU ordering and evicts oldest record if capacity is exceeded.
        
        Strictly validates increment and timestamp BEFORE altering internal table state,
        guaranteeing that invalid inputs cannot corrupt scores or change LRU order.
        """
        # Validate inputs BEFORE acquiring lock or touching state
        if key is None:
            raise ValueError("key cannot be None")
        valid_increment = _validate_numeric_increment(increment)
        now = _validate_timestamp(current_time) if current_time is not None else time.time()

        with self._lock:
            self._metrics.total_record_calls += 1

            if key in self._table:
                # Cache hit: update decay and move to most recent
                self._metrics.hits += 1
                entry = self._table.pop(key)
                dt = max(0.0, now - entry.last_seen)
                decayed = entry.decayed_score * math.exp(-self.decay_lambda * dt)
                entry.decayed_score = round(decayed + valid_increment, 6)
                entry.attempt_count += valid_increment
                entry.last_seen = now
                if metadata:
                    entry.metadata.update(metadata)
                self._table[key] = entry
                return entry

            # Cache miss: check capacity and evict LRU if full
            self._metrics.misses += 1
            if len(self._table) >= self.max_entries:
                # Evict least-recently-used item (first in OrderedDict)
                evicted_key, _ = self._table.popitem(last=False)
                self._metrics.evictions += 1
                log.debug(f"State table capacity reached ({self.max_entries}). Evicted LRU key: {evicted_key}")

            new_entry = ConnectionStateEntry(
                key=key,
                first_seen=now,
                last_seen=now,
                attempt_count=valid_increment,
                decayed_score=round(valid_increment, 6),
                metadata=metadata or {},
                ttl_seconds=self.default_ttl,
            )
            self._table[key] = new_entry
            self._metrics.current_entries = len(self._table)
            return new_entry

    def get(self, key: Union[str, Tuple[Any, ...]], current_time: Optional[float] = None) -> Optional[ConnectionStateEntry]:
        """
        Retrieves the state entry for a key if present and not expired.
        Updates LRU order upon access.
        """
        now = _validate_timestamp(current_time) if current_time is not None else time.time()
        with self._lock:
            if key not in self._table:
                self._metrics.misses += 1
                return None

            entry = self._table[key]
            # Check expiration
            if entry.ttl_seconds and (now - entry.last_seen > entry.ttl_seconds):
                # Entry is expired
                del self._table[key]
                self._metrics.expired_purges += 1
                self._metrics.current_entries = len(self._table)
                self._metrics.misses += 1
                return None

            # Mark recently used
            self._table.move_to_end(key, last=True)
            self._metrics.hits += 1
            return entry

    def purge_expired(self, current_time: Optional[float] = None) -> int:
        """Purges all expired entries from the table."""
        now = _validate_timestamp(current_time) if current_time is not None else time.time()
        purged = 0
        with self._lock:
            keys_to_delete = [
                k for k, entry in self._table.items()
                if entry.ttl_seconds and (now - entry.last_seen > entry.ttl_seconds)
            ]
            for k in keys_to_delete:
                del self._table[k]
                purged += 1

            self._metrics.expired_purges += purged
            self._metrics.current_entries = len(self._table)
            self._metrics.last_purge_timestamp = now
        return purged

    def clear(self) -> None:
        """Clears all entries and resets the table."""
        with self._lock:
            self._table.clear()
            self._metrics.current_entries = 0

    def get_metrics(self) -> Dict[str, Any]:
        """Returns snapshot of operational state metrics."""
        with self._lock:
            return {
                "max_entries": self._metrics.max_entries,
                "current_entries": len(self._table),
                "total_record_calls": self._metrics.total_record_calls,
                "hits": self._metrics.hits,
                "misses": self._metrics.misses,
                "evictions": self._metrics.evictions,
                "expired_purges": self._metrics.expired_purges,
                "hit_rate": round(self._metrics.hits / max(1, self._metrics.hits + self._metrics.misses), 4),
            }
