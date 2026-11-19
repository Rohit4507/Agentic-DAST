"""Proof capsules, minimum-evidence extraction, negative controls, replay.

Three rules this module enforces on every finding:

1. **No status-code-only findings.** A 200 means nothing until the body proves *whose*
   object came back. The research pack's trap: *"it returns a passwd file, but it's the
   attacker's passwd file."*
2. **Every test carries a negative control.** Request a non-existent object first; if it
   also returns 200, the test is broken, not the app. A failed control voids the finding.
3. **Minimum evidence.** Bodies are truncated, PII is masked, and the capsule stores the
   exact replayable request/response pair -- never a bulk dump.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from ..audit import redact_headers, redact_url
from ..errors import ControlFailure, DastError, ScopeViolation, TransportError, STOPPING
from ..http import Client, Response
from ..model import iso, utcnow

PII_KEYS = {
    "passport",
    "passportno",
    "passportnumber",
    "email",
    "phone",
    "mobile",
    "dob",
    "dateofbirth",
    "address",
    "card",
    "cardnumber",
    "pan",
    "cvv",
    "ssn",
    "name",
}
MAX_EXCERPT_CHARS = 1200
MAX_EXCERPT_LINES = 14


# --------------------------------------------------------------------------------------
# redaction / minimal evidence
# --------------------------------------------------------------------------------------


def mask_value(value: Any) -> str:
    text = str(value)
    if len(text) <= 3:
        return "*" * len(text)
    return f"{text[:3]}{'*' * min(len(text) - 3, 8)} (len={len(text)})"


def redact_body(obj: Any, *, depth: int = 0) -> tuple[Any, int]:
    """Recursively mask values of PII-looking keys, keeping the keys themselves.

    Keeping the key is the point: it proves *what* was exposed without copying it.
    """
    redactions = 0
    if depth > 6:
        return "<truncated>", 0
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for k, v in obj.items():
            if str(k).lower().replace("_", "") in PII_KEYS and not isinstance(v, (dict, list)):
                out[str(k)] = mask_value(v)
                redactions += 1
            else:
                out[str(k)], n = redact_body(v, depth=depth + 1)
                redactions += n
        return out, redactions
    if isinstance(obj, list):
        trimmed = obj[:5]
        redactions = len(obj) - len(trimmed) if len(obj) > len(trimmed) else 0
        out_list = []
        for item in trimmed:
            item_out, n = redact_body(item, depth=depth + 1)
            out_list.append(item_out)
            redactions += n
        return out_list, redactions
    return obj, 0


def excerpt(resp: Response, *, max_chars: int = MAX_EXCERPT_CHARS, max_lines: int = MAX_EXCERPT_LINES) -> tuple[str, int]:
    """A short, redacted, line-limited slice of the response body."""
    text = resp.text
    redactions = 0
    try:
        obj = json.loads(text)
        redacted, redactions = redact_body(obj)
        text = json.dumps(redacted, indent=2)
    except (json.JSONDecodeError, ValueError):
        text = _mask_text_secrets(text)
    lines = text.splitlines()[:max_lines]
    if len(text.splitlines()) > max_lines:
        lines.append(f"... ({len(text.splitlines()) - max_lines} more lines withheld: minimum evidence policy)")
    out = "\n".join(lines)
    if len(out) > max_chars:
        out = out[:max_chars] + "\n... (truncated)"
    return out, redactions


_SECRETISH = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9\-._~+/=]{4,}")


def _mask_text_secrets(text: str) -> str:
    return _SECRETISH.sub(lambda m: f"{m.group(1)} <redacted>", text)


def response_signature(resp: Response) -> dict[str, Any]:
    """Stable fingerprint of a response, used to detect drift on retest."""
    keys: list[str] = []
    try:
        body = resp.json()
        if isinstance(body, dict):
            keys = sorted(body)
    except ValueError:
        pass
    return {
        "status": resp.status,
        "content_type": resp.content_type,
        "bytes": len(resp.body),
        "keys": keys,
    }


# --------------------------------------------------------------------------------------
# negative control
# --------------------------------------------------------------------------------------


@dataclass
class ControlResult:
    path: str
    status: int
    expected: tuple[int, ...]
    passed: bool
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "status": self.status,
            "expected": list(self.expected),
            "passed": self.passed,
            "detail": self.detail,
        }


def negative_control(
    client: Client,
    template_path: str,
    *,
    role: str | None = None,
    expected: Iterable[int] = (404,),
    synthetic_id: str = "990001",
) -> ControlResult:
    """Request an object that must not exist, and assert it is refused.

    If this control returns 200, the endpoint answers *anything* -- so a 200 for a real
    object proves nothing and the finding must be dropped. Raises
    :class:`ControlFailure` when the control is inconclusive.
    """
    expected = tuple(expected)
    if "{id}" not in template_path:
        # No object identifier to vary, so a "does it answer anything?" control cannot
        # be built. Say so instead of pretending. The proof then rests on something
        # else -- for exposure tests, that no credential was sent at all.
        return ControlResult(
            path=template_path,
            status=0,
            expected=expected,
            passed=True,
            detail="not applicable: the route carries no object identifier; the proof rests on "
                   "the request carrying no credential",
        )
    path = template_path.replace("{id}", synthetic_id)
    try:
        resp = client.get(path, role=role, component="verifier", note="negative-control")
    except STOPPING:
        raise  # never downgrade "stop the engagement" into "inconclusive test"
    except ScopeViolation as exc:
        # Out-of-scope control is not a failed control; it is an inconclusive one.
        raise ControlFailure(f"negative control refused by scope guard: {exc.reason}") from exc
    except TransportError as exc:
        raise ControlFailure(f"negative control could not be delivered: {exc}") from exc

    passed = resp.status in expected
    result = ControlResult(
        path=path,
        status=resp.status,
        expected=expected,
        passed=passed,
        detail="" if passed else f"expected one of {expected}, got {resp.status}",
    )
    if not passed:
        raise ControlFailure(
            f"negative control failed: {path} -> {resp.status} (expected {expected}). "
            "The endpoint answers non-existent objects, so a 200 on a real object is not proof."
        )
    return result


# --------------------------------------------------------------------------------------
# proof capsules
# --------------------------------------------------------------------------------------


@dataclass
class CapsuleStep:
    label: str
    role: str | None
    method: str
    path: str
    status: int
    signature: dict[str, Any]
    body_excerpt: str
    redactions: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "role": self.role or "<anonymous>",
            "request": {"method": self.method, "path": redact_url(self.path)},
            "response": {
                "status": self.status,
                "signature": self.signature,
                "body_excerpt": self.body_excerpt,
                "redactions": self.redactions,
            },
        }


@dataclass
class Capsule:
    """A replayable proof of one finding.

    On retest we re-run :func:`replay_capsule`; if the flawed behaviour is gone the
    finding auto-closes. No human has to re-derive the bug.
    """

    finding_id: str
    title: str
    endpoint: str
    method: str
    steps: list[CapsuleStep] = field(default_factory=list)
    expected: dict[str, Any] = field(default_factory=dict)
    control: ControlResult | None = None
    created_at: str = field(default_factory=lambda: iso(utcnow()))
    version: int = 1

    def add(self, label: str, resp: Response, *, role: str | None = None) -> CapsuleStep:
        body, n = excerpt(resp)
        step = CapsuleStep(
            label=label,
            role=role,
            method=resp.method,
            path=resp.url,
            status=resp.status,
            signature=response_signature(resp),
            body_excerpt=body,
            redactions=n,
        )
        self.steps.append(step)
        return step

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "finding_id": self.finding_id,
            "title": self.title,
            "created_at": self.created_at,
            "endpoint": self.endpoint,
            "method": self.method,
            "expected": self.expected,
            "negative_control": self.control.to_dict() if self.control else None,
            "steps": [s.to_dict() for s in self.steps],
        }

    def curl_hint(self) -> str:
        """A ready-to-paste reproduction command (token read from the environment)."""
        if not self.steps:
            return ""
        s = self.steps[-1]  # the step that demonstrates the flaw, not the baseline
        role_env = f"${s.role.upper()}_TOKEN" if s.role else ""
        hdr = f" -H 'Authorization: Bearer {role_env}'" if role_env else ""
        return f"curl -s -o /dev/null -w '%{{http_code}}\\n'{hdr} '{redact_url(s.path)}'"


def replay_capsule(capsule: Capsule, client: Client) -> tuple[bool, str]:
    """Re-run the capsule's steps. Returns ``(still_vulnerable, detail)``."""
    if not capsule.steps:
        return False, "capsule has no steps to replay"
    primary = capsule.steps[-1]
    try:
        resp = client.request(
            primary.method,
            primary.path,
            role=primary.role,
            component="retest",
            note=f"retest:{capsule.finding_id}",
        )
    except (ScopeViolation, TransportError) as exc:
        return False, f"retest could not run: {exc}"

    want_status = capsule.expected.get("status", primary.status)
    if resp.status != want_status:
        return False, f"resolved: status {resp.status} != expected {want_status}"

    field_name = capsule.expected.get("identity_field")
    field_value = capsule.expected.get("identity_value")
    if field_name:
        try:
            body = resp.json()
        except ValueError:
            return False, "resolved: response is no longer JSON"
        actual = body.get(field_name) if isinstance(body, dict) else None
        if str(actual) != str(field_value):
            return False, f"resolved: {field_name}={actual!r}, expected {field_value!r}"

    return True, "still exploitable: same response shape as the original proof"


# --------------------------------------------------------------------------------------
# evidence assembly
# --------------------------------------------------------------------------------------


def build_evidence(
    capsule: Capsule,
    *,
    extracted: dict[str, Any] | None = None,
) -> Any:
    """Convert a capsule into the Finding's :class:`~dast.model.Evidence`."""
    from ..model import Evidence

    primary = capsule.steps[-1] if capsule.steps else None
    if primary is None:
        raise DastError("cannot build evidence without at least one capsule step")
    return Evidence(
        request={
            "method": primary.method,
            "path": redact_url(primary.path),
            "role": primary.role or "<anonymous>",
            "credential": f"<{primary.role} token from env>",
            "reproduce": capsule.curl_hint(),
        },
        response={
            "status": primary.status,
            "signature": primary.signature,
            "excerpt": primary.body_excerpt,
            "redactions": sum(s.redactions for s in capsule.steps),
        },
        extracted=extracted or {},
        redactions=sum(s.redactions for s in capsule.steps),
    )


def compare_identity(
    owner_resp: Response, other_resp: Response, *, identity_field: str = "bookingId"
) -> dict[str, Any] | None:
    """Prove that ``other_resp`` returned the *same object* as ``owner_resp``.

    Returns the extracted cross-boundary facts, or ``None`` if the responses are not
    the same object (i.e. not a finding).
    """
    try:
        a, b = owner_resp.json(), other_resp.json()
    except ValueError:
        return None
    if not isinstance(a, dict) or not isinstance(b, dict):
        return None
    if str(a.get(identity_field)) != str(b.get(identity_field)) or a.get(identity_field) is None:
        return None
    return {
        "identity_field": identity_field,
        "identity_value": a.get(identity_field),
        "owner_view_keys": sorted(a),
        "other_view_keys": sorted(b),
    }


def headers_for(capsule: Capsule) -> dict[str, str]:
    return redact_headers({s.label: s.role or "" for s in capsule.steps})
