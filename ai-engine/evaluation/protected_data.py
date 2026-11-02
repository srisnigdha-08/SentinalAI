"""
The prospective final external test (audit/ML_DEV_PROTOCOL.md): four CSE-CIC-IDS2018 capture days that have never
been downloaded, inspected or scored by this project. No development code may read them; every loader calls
assert_permitted() on each path before opening it. Lifting this guard is a deliberate, approved step (the
final-evaluation script sets SENTINEL_FINAL_EXTERNAL_EVAL=I_HAVE_APPROVAL and records that it did).
"""
import os
import re
from pathlib import Path

PROTECTED_DAYS = ("16-02-2018", "20-02-2018", "22-02-2018", "28-02-2018")
_PATTERN = re.compile("|".join(re.escape(d) for d in PROTECTED_DAYS))
APPROVAL_VALUE = "I_HAVE_APPROVAL"


class ProtectedDataError(RuntimeError):
    pass


def is_protected(path) -> bool:
    return bool(_PATTERN.search(Path(str(path)).name))


def assert_permitted(path, *, final_evaluation: bool = False):
    """Raise unless `path` may be used for development. final_evaluation=True only with the explicit approval value
    in SENTINEL_FINAL_EXTERNAL_EVAL (the one-shot external test, after candidates are frozen)."""
    if not is_protected(path):
        return
    if final_evaluation and os.getenv("SENTINEL_FINAL_EXTERNAL_EVAL") == APPROVAL_VALUE:
        return
    raise ProtectedDataError(f"{Path(str(path)).name} is part of the protected final external test set "
                             f"({', '.join(PROTECTED_DAYS)}); development code may not read it")


def permitted_files(directory, pattern="*.csv"):
    """Files in `directory` that development may use; protected files are skipped (and named) rather than read."""
    files = sorted(Path(directory).glob(pattern))
    return [f for f in files if not is_protected(f)], [f.name for f in files if is_protected(f)]
