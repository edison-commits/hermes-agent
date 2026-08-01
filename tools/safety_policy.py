"""Small, local-first safety policy primitives inspired by QM.

This module is deliberately policy-only: callers decide when to apply a policy.
It gives Hermes stable labels for external context, a conservative audience
floor for fan-out, and deterministic host egress decisions.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse

PROVENANCE_LABELS = frozenset({
    "user_instruction",
    "system_instruction",
    "project_file",
    "tool_output",
    "web_content",
    "external_file",
    "external_repo",
    "model_generated",
})
_UNTRUSTED = frozenset({"tool_output", "web_content", "external_file", "external_repo", "model_generated"})


def provenance_label(source: str) -> str:
    """Classify a source reference without trusting its contents."""
    value = (source or "").strip().lower()
    if value.startswith(("http://", "https://")):
        return "web_content"
    if value.startswith(("git://", "git@", "github.com/", "gitlab.com/")):
        return "external_repo"
    if value.startswith(("/", "./", "../", "~")):
        return "external_file"
    return value if value in PROVENANCE_LABELS else "tool_output"


def is_untrusted(label: str) -> bool:
    return (label or "").strip().lower() in _UNTRUSTED


_AUDIENCE_RANK = {"private": 0, "shared": 1, "public": 2}


def audience_floor(audiences: list[str] | tuple[str, ...]) -> str:
    """Return the least-public audience safe for every recipient.

    Unknown or empty audiences are conservatively treated as private.
    """
    normalized = [str(a).strip().lower() for a in audiences if str(a).strip()]
    if not normalized or any(a not in _AUDIENCE_RANK for a in normalized):
        return "private"
    return min(normalized, key=lambda a: _AUDIENCE_RANK[a])


def _normalize_host(host: str) -> str:
    value = (host or "").strip().lower().rstrip(".")
    if not value or any(c in value for c in " /?#@") or "://" in value or "*" in value:
        raise ValueError(f"{host!r} is not a host name")
    if value.count(":") == 1:
        raise ValueError(f"{host!r} includes a port; use a host name only")
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    if ":" not in value and not re.fullmatch(r"(?:[a-z0-9-]+\.)*[a-z0-9-]+", value):
        raise ValueError(f"{host!r} is not a host name")
    return value


def _host_matches(host: str, rule: str) -> bool:
    actual = _normalize_host(host)
    expected = _normalize_host(rule)
    return actual == expected or actual.endswith("." + expected)


@dataclass(frozen=True)
class AttributionDecision:
    allow: bool
    verdict: str


_PRECISE_ATTRIBUTION_SOURCES = frozenset({
    "direct_human", "delegation", "comment_source", "trigger_owner", "rule_owner",
})


def attribution_decision(source: str, *, strict: bool = False) -> AttributionDecision:
    """Decide whether an action has sufficiently precise human attribution."""
    normalized = (source or "").strip().lower()
    precise = normalized in _PRECISE_ATTRIBUTION_SOURCES
    if strict and not precise:
        return AttributionDecision(False, "imprecise")
    return AttributionDecision(True, "precise" if precise else "degraded")


@dataclass(frozen=True)
class EgressPolicy:
    allowed_hosts: tuple[str, ...] = ()
    denied_hosts: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        allowed = tuple(_normalize_host(h) for h in self.allowed_hosts)
        denied = tuple(_normalize_host(h) for h in self.denied_hosts)
        overlap = set(allowed) & set(denied)
        if overlap:
            raise ValueError(f"host appears in both allow and deny lists: {sorted(overlap)[0]}")
        object.__setattr__(self, "allowed_hosts", allowed)
        object.__setattr__(self, "denied_hosts", denied)


def parse_egress_policy(value: object) -> EgressPolicy:
    if not isinstance(value, dict):
        raise ValueError("egress policy requires an object")
    allowed = value.get("allowedHosts", value.get("allowed_hosts", ()))
    denied = value.get("deniedHosts", value.get("denied_hosts", ()))
    if not isinstance(allowed, (list, tuple)) or not isinstance(denied, (list, tuple)):
        raise ValueError("host allow and deny lists must be arrays")
    return EgressPolicy(tuple(str(h) for h in allowed), tuple(str(h) for h in denied))


@dataclass(frozen=True)
class EgressDecision:
    allow: bool
    verdict: str


def egress_decision(host: str, policy: EgressPolicy | None) -> EgressDecision:
    if policy is None:
        return EgressDecision(True, "ok")
    if any(_host_matches(host, rule) for rule in policy.denied_hosts):
        return EgressDecision(False, "denied")
    if policy.allowed_hosts and not any(_host_matches(host, rule) for rule in policy.allowed_hosts):
        return EgressDecision(False, "not_allowlisted")
    return EgressDecision(True, "ok")


__all__ = [
    "AttributionDecision",
    "EgressDecision",
    "EgressPolicy",
    "audience_floor",
    "egress_decision",
    "is_untrusted",
    "parse_egress_policy",
    "provenance_label",
]
