"""Shared helpers for the API routers."""

from __future__ import annotations

from fastapi import Request

DEFAULT_OPERATOR = "Duty Officer"


def operator_of(request: Request) -> str:
    """Operator name for the custody trail. Sent by the dashboard as the
    X-Operator header; it is attribution, not authentication (the API key
    is the access control)."""
    name = request.headers.get("x-operator") or request.query_params.get("operator") or DEFAULT_OPERATOR
    name = "".join(ch for ch in name if ch.isprintable()).strip()[:40]
    return name or DEFAULT_OPERATOR
