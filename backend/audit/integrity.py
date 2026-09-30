"""
SentinelGate — Audit Log Integrity & HMAC Chaining
==================================================
Cryptographic tamper-evidence for security audit records using HMAC-SHA256 chaining.
Each record's hash depends on:
- SECRET_KEY
- Previous record's HMAC (chain linkage)
- Request ID
- Timestamp
- Risk Score
- Action Taken

Verification validates whether any event in the historical chain has been altered,
inserted, or deleted.
"""
from __future__ import annotations

import hashlib
import hmac
from datetime import datetime, timezone
from typing import Any

from backend.config import get_settings


def normalize_timestamp_str(timestamp: datetime | str) -> str:
    """
    Normalize timestamp to ISO 8601 UTC representation (%Y-%m-%dT%H:%M:%SZ).
    Ensures deterministic HMAC hashing regardless of DB storage formatting (SQLite vs Postgres).
    """
    if isinstance(timestamp, str):
        try:
            dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError:
            return timestamp
    else:
        dt = timestamp

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)

    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def compute_event_hmac(
    prev_hmac: str,
    request_id: str,
    timestamp: datetime | str,
    risk_score: int,
    action: str,
    secret_key: str | None = None,
) -> str:
    """
    Compute HMAC-SHA256 hash for a security event record.

    Formula:
        HMAC = HMAC-SHA256(key, prev_hmac + request_id + timestamp + risk_score + action)
    """
    if secret_key is None:
        secret_key = get_settings().secret_key

    ts_str = normalize_timestamp_str(timestamp)
    raw_message = f"{prev_hmac}{request_id}{ts_str}{risk_score}{action}"
    return hmac.new(
        secret_key.encode("utf-8"),
        raw_message.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def verify_hmac_chain(
    events: list[Any],
    secret_key: str | None = None,
    initial_hmac: str = "",
) -> dict[str, Any]:
    """
    Verify the cryptographic integrity of an ordered sequence of SecurityEvent records.
    Events MUST be provided in chronological order (oldest to newest).

    Returns:
        dict:
            verified (bool): True if all records match the expected HMAC chain.
            total_events (int): Number of events checked.
            tampered_events (list[dict]): Details of any events where the hash failed.
    """
    if secret_key is None:
        secret_key = get_settings().secret_key

    prev_hmac = initial_hmac
    tampered_events: list[dict[str, Any]] = []

    for idx, event in enumerate(events):
        ts = getattr(event, "timestamp")
        ts_str = normalize_timestamp_str(ts)
        req_id = str(getattr(event, "request_id"))
        score = int(getattr(event, "risk_score"))
        act = str(getattr(event, "action"))
        actual_hmac = getattr(event, "hmac_chain", None) or ""

        expected_hmac = compute_event_hmac(
            prev_hmac=prev_hmac,
            request_id=req_id,
            timestamp=ts_str,
            risk_score=score,
            action=act,
            secret_key=secret_key,
        )

        if not hmac.compare_digest(actual_hmac, expected_hmac):
            tampered_events.append({
                "index": idx,
                "event_id": str(getattr(event, "id", "")),
                "request_id": req_id,
                "expected_hmac": expected_hmac,
                "actual_hmac": actual_hmac,
            })
            # To isolate individual tampered items, update prev_hmac with actual
            prev_hmac = actual_hmac
        else:
            prev_hmac = actual_hmac

    return {
        "verified": len(tampered_events) == 0,
        "total_events": len(events),
        "tampered_events": tampered_events,
    }
