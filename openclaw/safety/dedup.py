"""Candidate dedup. Prevents the agent from re-creating the same finding
across runs or within a single run.

Fingerprint = sha256(vuln_class + normalized_url + normalized_evidence_key).

Stored as 'dedup_key' rows in memory table. On new candidate creation, check
fingerprint against memory; if present, block insertion and log as `dup_self`.
"""
from __future__ import annotations
import hashlib
import json
import re
from urllib.parse import urlparse
from openclaw.db import client as db


def _normalize_url(url: str) -> str:
    """Strip query string and fragment; lowercase host; collapse trailing slashes.
    Also collapses numeric path segments to `{id}` so /users/123 == /users/456."""
    if not url:
        return ""
    try:
        u = urlparse(url)
        host = (u.hostname or "").lower()
        port = f":{u.port}" if u.port else ""
        path = u.path or "/"
        # Collapse numeric segments and UUIDs
        path = re.sub(r"/\d+(?=/|$)", "/{id}", path)
        path = re.sub(
            r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?=/|$)",
            "/{uuid}", path, flags=re.I,
        )
        path = path.rstrip("/") or "/"
        return f"{u.scheme}://{host}{port}{path}"
    except Exception:
        return url


def _stable_evidence_summary(evidence: dict | str) -> str:
    """Pull a stable signal from evidence for fingerprinting.

    We don't want every response-body byte to change the fingerprint
    (defeats dedup on semantically-same finding). Pick a few deterministic
    fields if present.
    """
    if isinstance(evidence, str):
        try:
            evidence = json.loads(evidence)
        except json.JSONDecodeError:
            return evidence[:200]
    if not isinstance(evidence, dict):
        return ""

    stable_keys = ("template", "template_id", "matcher", "name", "cwe",
                   "signature", "param", "header", "error_signature")
    parts = []
    for k in stable_keys:
        if k in evidence:
            parts.append(f"{k}={evidence[k]}")
    return "|".join(parts)


def fingerprint(vuln_class: str, affected_url: str, evidence: dict | str) -> str:
    normalized = "::".join([
        (vuln_class or "").lower().strip(),
        _normalize_url(affected_url),
        _stable_evidence_summary(evidence),
    ])
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:32]


def is_duplicate(scope: str, fp: str) -> bool:
    """Check if a fingerprint is already recorded for this scope."""
    rows = db.recall_memory(scope=scope, kind="dedup_key", limit=10000)
    return any(m["content"] == fp for m in rows)


def remember(scope: str, fp: str) -> None:
    db.add_memory(scope=scope, kind="dedup_key", content=fp)


def check_and_remember(
    scope: str,
    vuln_class: str,
    affected_url: str,
    evidence: dict | str,
) -> tuple[bool, str]:
    """Returns (was_duplicate, fingerprint).

    If dup: does not re-remember (no-op).
    If new: remembers the fingerprint before returning.
    """
    fp = fingerprint(vuln_class, affected_url, evidence)
    if is_duplicate(scope, fp):
        return True, fp
    remember(scope, fp)
    return False, fp
