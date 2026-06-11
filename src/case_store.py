"""JSON-backed store for analyst case state.

Persists per-alert working state across dashboard sessions: lifecycle
status, assignee, notes, and analyst feedback on the AI verdict. Keyed by
dataset (hash of the log content) so the same IP in different datasets has
independent case state.
"""
import json
import os
import threading
from datetime import datetime

STORE_PATH = os.path.join("data", "case_state.json")
_lock = threading.Lock()

STATUSES = ["New", "Investigating", "Contained", "Closed"]
STATUS_ICON = {"New": "⚪", "Investigating": "🔵", "Contained": "🟠", "Closed": "🟢"}


def _load() -> dict:
    if os.path.exists(STORE_PATH):
        try:
            with open(STORE_PATH) as f:
                return json.load(f)
        except ValueError:
            return {}
    return {}


def get_cases(dataset_key: str) -> dict:
    """All case records for one dataset: {src_ip: {status, assignee, ...}}."""
    return _load().get(dataset_key, {})


def update_case(dataset_key: str, src_ip: str, **fields) -> None:
    with _lock:
        data = _load()
        case = data.setdefault(dataset_key, {}).setdefault(src_ip, {})
        case.update(fields)
        case["updated_at"] = datetime.now().isoformat(timespec="seconds")
        with open(STORE_PATH, "w") as f:
            json.dump(data, f, indent=2)
