"""
SentinelGate — Evasion Normalization Pipeline
==============================================
Normalizes all inspectable request components before pattern matching.
Closes evasion loopholes:
- Loophole 6: Double-encoded attack evasion (%2527 -> %27 -> ')
- Loophole 7: Unicode normalization evasion (NFC)
- Null byte injection (\x00, %00)
- HTML entity encoding (&lt; -> <, &#x27; -> ')
"""
from __future__ import annotations

import html
import unicodedata
import urllib.parse
from dataclasses import dataclass
from typing import Any

import orjson

from backend.schemas.context import GatewayContext


@dataclass(slots=True)
class InspectionTarget:
    """A single inspectable target location with raw and normalized text."""
    location: str
    raw_value: str
    normalized_value: str


def normalize_text(text: str) -> str:
    """
    Apply strict sequential normalization:
    1. URL percent-decode (once)
    2. URL percent-decode (twice, catches double-encoding)
    3. HTML entity decode (&lt; -> <, &#x27; -> ', etc.)
    4. Unicode normalization (NFC)
    5. Remove null bytes (\\x00, %00)
    6. Strip excess whitespace and lowercase
    """
    if not text:
        return ""

    # 1. First URL decode
    try:
        s = urllib.parse.unquote(text)
    except Exception:
        s = text

    # 2. Second URL decode (catches double-encoding like %252e%252e or %2527)
    try:
        s = urllib.parse.unquote(s)
    except Exception:
        pass

    # 3. HTML entity decode
    try:
        s = html.unescape(s)
    except Exception:
        pass

    # 4. Unicode normalization (NFC)
    s = unicodedata.normalize("NFC", s)

    # 5. Remove null bytes
    s = s.replace("\x00", "").replace("%00", "")

    # 6. Lowercase
    return s.lower()


def _flatten_json(data: Any, prefix: str = "") -> list[tuple[str, str]]:
    """Recursively flatten JSON dict/list structures into (path, str_value) pairs."""
    items: list[tuple[str, str]] = []
    if isinstance(data, dict):
        for k, v in data.items():
            field_name = f"{prefix}.{k}" if prefix else str(k)
            # Also inspect the dictionary key itself
            items.append((f"{field_name}_key", str(k)))
            items.extend(_flatten_json(v, field_name))
    elif isinstance(data, list):
        for idx, item in enumerate(data):
            field_name = f"{prefix}[{idx}]"
            items.extend(_flatten_json(item, field_name))
    elif data is not None:
        items.append((prefix, str(data)))
    return items


def extract_inspection_targets(ctx: GatewayContext) -> list[InspectionTarget]:
    """
    Extract and normalize all inspectable components of a GatewayContext:
    - Path
    - Query parameters (keys and values)
    - Headers (User-Agent, Referer, Cookie, etc.)
    - Request body (JSON, form-encoded, raw)
    """
    targets: list[InspectionTarget] = []

    # 1. URL Path
    targets.append(
        InspectionTarget(
            location="path",
            raw_value=ctx.path,
            normalized_value=normalize_text(ctx.path),
        )
    )

    # 2. Query Parameters
    for k, v in ctx.query_params.items():
        val_str = str(v)
        # Inspect parameter key
        targets.append(
            InspectionTarget(
                location=f"query_key:{k}",
                raw_value=k,
                normalized_value=normalize_text(k),
            )
        )
        # Inspect parameter value
        targets.append(
            InspectionTarget(
                location=f"query:{k}",
                raw_value=val_str,
                normalized_value=normalize_text(val_str),
            )
        )

    # 3. Headers
    for header_name, header_val in ctx.headers.items():
        targets.append(
            InspectionTarget(
                location=f"header:{header_name}",
                raw_value=header_val,
                normalized_value=normalize_text(header_val),
            )
        )

    # 4. Request Body
    if ctx.body and len(ctx.body) > 0:
        raw_body_text = ctx.body.decode("utf-8", errors="replace")
        targets.append(
            InspectionTarget(
                location="body:raw",
                raw_value=raw_body_text,
                normalized_value=normalize_text(raw_body_text),
            )
        )

        # Try parsing as JSON
        try:
            parsed_json = orjson.loads(ctx.body)
            flattened = _flatten_json(parsed_json, prefix="body")
            for loc, val in flattened:
                targets.append(
                    InspectionTarget(
                        location=loc,
                        raw_value=val,
                        normalized_value=normalize_text(val),
                    )
                )
        except Exception:
            # If not JSON, try parsing as form-urlencoded
            try:
                parsed_form = urllib.parse.parse_qsl(raw_body_text, keep_blank_values=True)
                for form_k, form_v in parsed_form:
                    targets.append(
                        InspectionTarget(
                            location=f"body:{form_k}",
                            raw_value=form_v,
                            normalized_value=normalize_text(form_v),
                        )
                    )
            except Exception:
                pass

    return targets
