"""
MongoDB persistence for AgentBreak scan runs.

A scan produces one `runs` document (the summary: target config,
scenario, outcome, metrics) and many `trace_steps` documents (one per
event in the execution trace). Keeping steps in their own collection
means a long multi-turn trace never risks MongoDB's 16 MB document
limit and is easy to stream to the dashboard.

The Mongo client is owned by main.py and handed in via `init()` during
app startup, so this module shares the one connection instead of
opening a second. Every write is best-effort: if the database is
unavailable, a scan still returns its result and simply reports
`persisted: false`.
"""

from datetime import datetime, timezone
from typing import Any

from pymongo import ASCENDING, DESCENDING
from pymongo.errors import PyMongoError

RUNS = "runs"
TRACE_STEPS = "trace_steps"

_db = None

# Last persistence error, for diagnostics. None means the last
# save_run succeeded (or none has run yet).
last_error: str | None = None


def init(client, db_name: str) -> None:
    """Register the shared Mongo client and ensure indexes exist."""
    global _db
    _db = client[db_name]
    try:
        _db[TRACE_STEPS].create_index(
            [("run_id", ASCENDING), ("step", ASCENDING)],
            unique=True,
            name="run_step_unique",
        )
        _db[RUNS].create_index(
            [("started_at", DESCENDING)],
            name="runs_by_time",
        )
    except PyMongoError:
        # Indexes are an optimization; never block startup on them.
        pass


def available() -> bool:
    return _db is not None


def save_run(summary: dict[str, Any], events: list[dict[str, Any]]) -> bool:
    """
    Persist one scan. `summary` is the run document (no events);
    `events` are written separately as trace steps. Returns True only
    if the write succeeded. Idempotent on run_id: re-saving the same
    run replaces the prior copy and its steps.
    """
    global last_error
    last_error = None

    if _db is None:
        last_error = "storage not initialized: _db is None (lifespan init() did not run)"
        return False

    run_id = summary.get("run_id")
    if not run_id:
        last_error = "missing run_id in summary"
        return False

    try:
        doc = dict(summary)
        doc["_id"] = run_id
        doc["step_count"] = len(events)
        _db[RUNS].replace_one({"_id": run_id}, doc, upsert=True)

        _db[TRACE_STEPS].delete_many({"run_id": run_id})
        if events:
            now = datetime.now(timezone.utc)
            step_docs = [
                {
                    "run_id": run_id,
                    "step": event.get("step"),
                    "type": event.get("type"),
                    "message": event.get("message"),
                    "details": event.get("details", {}),
                    "ts": now,
                }
                for event in events
            ]
            _db[TRACE_STEPS].insert_many(step_docs)
        return True
    except PyMongoError as e:
        last_error = f"{type(e).__name__}: {e}"
        return False
    except Exception as e:  # noqa: BLE001 - diagnostics; never crash a scan
        last_error = f"{type(e).__name__}: {e}"
        return False


def list_runs(limit: int = 20) -> list[dict[str, Any]]:
    """Most recent runs first, summaries only (no trace steps)."""
    if _db is None:
        return []
    cursor = (
        _db[RUNS]
        .find({}, {"_id": 0})
        .sort("started_at", DESCENDING)
        .limit(min(max(limit, 1), 100))
    )
    return list(cursor)


def get_run(run_id: str) -> dict[str, Any] | None:
    """One run summary, or None if it doesn't exist."""
    if _db is None:
        return None
    return _db[RUNS].find_one({"_id": run_id}, {"_id": 0})


def get_trace(run_id: str) -> list[dict[str, Any]]:
    """The ordered trace steps for a run."""
    if _db is None:
        return []
    cursor = (
        _db[TRACE_STEPS]
        .find({"run_id": run_id}, {"_id": 0, "run_id": 0})
        .sort("step", ASCENDING)
    )
    return list(cursor)