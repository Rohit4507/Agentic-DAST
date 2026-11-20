"""The target profile: what a specific API calls its things.

The scanner's *logic* -- state machine, invariants, capsules, approval gate -- is
target-independent.  What is not target-independent is vocabulary: which path holds a
refund, what the request body looks like, which JSON key carries the object id, where
the tenant boundary lives, and how to read a ledger back.

Version 1 of this tool hard-coded that vocabulary to the bundled mock, which meant a
different API produced a flat "0 findings" instead of a parse error.  A profile moves
the vocabulary into a JSON file a human writes, validated fail-closed:

    python run.py all --scope scope2.json      # scope2.json names its profile

Design rules, all of them borrowed from :mod:`dast.scope`:

* **Unknown keys are fatal.**  A typo in ``identifiers.boundary_field`` must not
  silently degrade into "no cross-tenant findings".
* **Missing is allowed, guessing is not.**  A profile without a ``rebook`` step simply
  does not plan the fare-tampering test, and says so.
* **No placeholders are invented at runtime.**  Only the names in
  :data:`PLACEHOLDERS` may appear in a template, and they are checked at load.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping

from .errors import DastError

#: Values a step template may interpolate.  Anything else is a load-time error.
PLACEHOLDERS = frozenset({"id", "amount", "pax", "quoted", "tampered"})

#: Flow steps the planner knows how to use.
FLOW_STEPS = ("hold", "pay", "confirm", "cancel", "refund", "rebook", "ledger")

_PLACEHOLDER = re.compile(r"\{([a-z_]+)\}")

_TOP_KEYS = {"name", "description", "flows", "identifiers", "agency", "ledger", "bola", "bundle"}
_STEP_KEYS = {"path", "method", "body", "id_from", "note"}
_IDENT_KEYS = {"identity_field", "boundary_field", "identity_candidates", "boundary_candidates", "object_noun"}
_AGENCY_KEYS = {"probe_paths", "fields"}
_LEDGER_KEYS = {"adapter", "endpoint", "path", "map", "item_map", "id_field"}
_BOLA_KEYS = {"exclude_templates", "max_targets_per_id"}
_BUNDLE_KEYS = {"route_prefixes"}


def _fail(msg: str) -> None:
    raise DastError(f"profile: {msg}")


def _check_keys(raw: Mapping[str, Any], allowed: Iterable[str], where: str) -> None:
    unknown = sorted(set(raw) - set(allowed))
    if unknown:
        _fail(f"unknown key(s) {unknown} in {where}; allowed: {sorted(allowed)}")


def _str_list(value: Any, where: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
        _fail(f"{where} must be a list of strings, got {type(value).__name__}")
    return tuple(value)


def _render(value: Any, ctx: Mapping[str, Any]) -> Any:
    """Substitute ``{id}``/``{amount}``/... into a body template.

    A value that is *exactly* one placeholder keeps the placeholder's type, so
    ``{"amount": "{amount}"}`` sends the JSON number ``1000.0`` rather than the string
    ``"1000.0"``.  Real APIs reject the string, and the finding then looks like a
    test failure rather than a schema mismatch.
    """
    if isinstance(value, str):
        whole = _PLACEHOLDER.fullmatch(value)
        if whole and whole.group(1) in ctx:
            return ctx[whole.group(1)]
        return _PLACEHOLDER.sub(lambda m: str(ctx.get(m.group(1), m.group(0))), value)
    if isinstance(value, Mapping):
        return {k: _render(v, ctx) for k, v in value.items()}
    if isinstance(value, list):
        return [_render(v, ctx) for v in value]
    return value


def _check_placeholders(text: Any, where: str) -> None:
    if isinstance(text, str):
        for name in _PLACEHOLDER.findall(text):
            if name not in PLACEHOLDERS:
                _fail(f"{where} uses unknown placeholder {{{name}}}; allowed: {sorted(PLACEHOLDERS)}")
    elif isinstance(text, Mapping):
        for v in text.values():
            _check_placeholders(v, where)
    elif isinstance(text, list):
        for v in text:
            _check_placeholders(v, where)


# --------------------------------------------------------------------------------------
# steps and flows
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class StepSpec:
    """One call the flow tests make, described as data."""

    name: str
    path: str
    method: str = "POST"
    body: Mapping[str, Any] = field(default_factory=dict)
    id_from: str = ""
    note: str = ""

    def url(self, **values: Any) -> str:
        return _render(self.path, values)

    def payload(self, **values: Any) -> dict[str, Any]:
        rendered = _render(self.body, values)
        return dict(rendered) if isinstance(rendered, Mapping) else {}

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "method": self.method,
            "body": dict(self.body),
            "id_from": self.id_from,
        }

    @classmethod
    def parse(cls, name: str, raw: Any, where: str) -> "StepSpec":
        if isinstance(raw, str):
            raw = {"path": raw}
        if not isinstance(raw, Mapping):
            _fail(f"{where} must be an object or a path string")
        _check_keys(raw, _STEP_KEYS, where)
        path = raw.get("path")
        if not isinstance(path, str) or not path.startswith("/"):
            _fail(f"{where}.path must be an absolute path string, got {path!r}")
        method = str(raw.get("method") or ("GET" if name == "ledger" else "POST")).upper()
        body = raw.get("body") or {}
        if not isinstance(body, Mapping):
            _fail(f"{where}.body must be an object")
        _check_placeholders(path, f"{where}.path")
        _check_placeholders(body, f"{where}.body")
        id_from = raw.get("id_from") or ""
        if not isinstance(id_from, str):
            _fail(f"{where}.id_from must be a string")
        return cls(
            name=name,
            path=path,
            method=method,
            body=dict(body),
            id_from=id_from,
            note=str(raw.get("note") or ""),
        )


@dataclass(frozen=True)
class FlowPathsView:
    """Read-only ``step name -> path`` view, for report text and retest lookups.

    Report copy says things like "POST /api/refund accepts a second refund"; keeping
    the paths reachable by attribute name means that copy keeps working when the
    target spells the step differently, instead of printing a stale mock path.
    """

    hold: str = ""
    pay: str = ""
    confirm: str = ""
    cancel: str = ""
    refund: str = ""
    rebook: str = ""
    ledger: str = ""

    def ledger_for(self, booking_id: str) -> str:
        return self.ledger.replace("{id}", str(booking_id))


@dataclass(frozen=True)
class FlowProfile:
    """The booking flow, as the target spells it.  Any step may be absent."""

    steps: Mapping[str, StepSpec] = field(default_factory=dict)

    def get(self, name: str) -> StepSpec | None:
        return self.steps.get(name)

    def view(self) -> FlowPathsView:
        return FlowPathsView(
            **{name: (self.steps[name].path if name in self.steps else "") for name in FLOW_STEPS}
        )

    def path(self, name: str) -> str:
        """Convenience for report text: the target's path, or a readable stand-in."""
        step = self.get(name)
        return step.path if step else f"<no {name} step configured>"

    def has(self, name: str) -> bool:
        return name in self.steps

    @property
    def missing(self) -> list[str]:
        return [s for s in FLOW_STEPS if s not in self.steps]

    @classmethod
    def parse(cls, raw: Any) -> "FlowProfile":
        if raw is None:
            return cls({})
        if not isinstance(raw, Mapping):
            _fail("flows must be an object keyed by step name")
        unknown = sorted(set(raw) - set(FLOW_STEPS))
        if unknown:
            _fail(f"unknown flow step(s) {unknown}; allowed: {list(FLOW_STEPS)}")
        steps = {name: StepSpec.parse(name, spec, f"flows.{name}") for name, spec in raw.items()}
        return cls(steps)


# --------------------------------------------------------------------------------------
# identifiers, agency, ledger, bola
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class IdentifierSpec:
    """Where the object identity and the tenant boundary live in a JSON body."""

    identity_field: str = "bookingId"
    boundary_field: str = "agencyId"
    identity_candidates: tuple[str, ...] = ()
    boundary_candidates: tuple[str, ...] = ()
    #: What the target calls the thing under test -- "booking", "order", "case".
    #: Used in titles and report prose so an orders API does not read as a travel one.
    object_noun: str = "booking"

    def identity_paths(self) -> tuple[str, ...]:
        """Explicit candidates first, then the field itself, then common synonyms."""
        seen: list[str] = []
        for p in (*self.identity_candidates, self.identity_field, "id", "booking_id", "_id"):
            if p and p not in seen:
                seen.append(p)
        return tuple(seen)

    def boundary_paths(self) -> tuple[str, ...]:
        seen: list[str] = []
        for p in (*self.boundary_candidates, self.boundary_field):
            if p and p not in seen:
                seen.append(p)
        return tuple(seen)

    def to_dict(self) -> dict[str, Any]:
        return {
            "identity_field": self.identity_field,
            "boundary_field": self.boundary_field,
            "identity_candidates": list(self.identity_candidates),
            "boundary_candidates": list(self.boundary_candidates),
            "object_noun": self.object_noun,
        }

    @classmethod
    def parse(cls, raw: Any) -> "IdentifierSpec":
        if raw is None:
            return cls()
        if not isinstance(raw, Mapping):
            _fail("identifiers must be an object")
        _check_keys(raw, _IDENT_KEYS, "identifiers")
        identity = raw.get("identity_field", cls.identity_field)
        boundary = raw.get("boundary_field", cls.boundary_field)
        for label, value in (("identity_field", identity), ("boundary_field", boundary)):
            if not isinstance(value, str) or not value:
                _fail(f"identifiers.{label} must be a non-empty dotted path string")
        noun = raw.get("object_noun", cls.object_noun)
        if not isinstance(noun, str) or not noun.strip():
            _fail("identifiers.object_noun must be a non-empty string")
        return cls(
            identity_field=identity,
            boundary_field=boundary,
            identity_candidates=_str_list(raw.get("identity_candidates"), "identifiers.identity_candidates"),
            boundary_candidates=_str_list(raw.get("boundary_candidates"), "identifiers.boundary_candidates"),
            object_noun=noun.strip(),
        )


@dataclass(frozen=True)
class AgencySpec:
    """How to learn which tenant a role belongs to without asking the operator."""

    probe_paths: tuple[str, ...] = ("/api/bookings", "/api/booking", "/api/me", "/api/agency/me")
    fields: tuple[str, ...] = ("agencyId", "agency", "tenantId", "tenant")

    def to_dict(self) -> dict[str, Any]:
        return {"probe_paths": list(self.probe_paths), "fields": list(self.fields)}

    @classmethod
    def parse(cls, raw: Any) -> "AgencySpec":
        if raw is None:
            return cls()
        if not isinstance(raw, Mapping):
            _fail("agency must be an object")
        _check_keys(raw, _AGENCY_KEYS, "agency")
        return cls(
            probe_paths=_str_list(raw.get("probe_paths"), "agency.probe_paths") or cls.probe_paths,
            fields=_str_list(raw.get("fields"), "agency.fields") or cls.fields,
        )


@dataclass(frozen=True)
class LedgerSpec:
    """How to read the money back, in whatever shape the target offers it.

    ``map``    -- canonical name -> dotted path in the target's response
    ``item_map`` -- canonical name -> key inside each row of a list

    Canonical names are the ones :class:`dast.verify.invariants.Ledger` already uses:
    ``status``, ``quotedAmount``, ``finalAmount``, ``paxCount``, ``payments``,
    ``refunds``; rows need ``amount`` and optionally ``status``.
    """

    adapter: str = "http"
    endpoint: str = ""
    path: str = ""
    map: Mapping[str, str] = field(default_factory=dict)
    item_map: Mapping[str, str] = field(default_factory=dict)
    id_field: str = "bookingId"

    @property
    def usable(self) -> bool:
        if self.adapter == "none":
            return False
        if self.adapter == "http":
            return bool(self.endpoint)
        if self.adapter == "fixture":
            return bool(self.path)
        return False

    def to_dict(self) -> dict[str, Any]:
        return {
            "adapter": self.adapter,
            "endpoint": self.endpoint,
            "path": self.path,
            "map": dict(self.map),
            "item_map": dict(self.item_map),
            "id_field": self.id_field,
        }

    @classmethod
    def parse(cls, raw: Any) -> "LedgerSpec":
        if raw is None:
            return cls(adapter="http", endpoint="/api/ledger/{id}")
        if isinstance(raw, str):
            # "none" is a declaration, not a path.  Anything else is a shorthand endpoint.
            if raw.strip().lower() == "none":
                return cls(adapter="none")
            raw = {"endpoint": raw}
        if not isinstance(raw, Mapping):
            _fail("ledger must be an object, a path string, or \"none\"")
        _check_keys(raw, _LEDGER_KEYS, "ledger")
        adapter = str(raw.get("adapter") or "http").lower()
        if adapter not in ("http", "fixture", "none"):
            _fail(f"ledger.adapter must be http, fixture or none; got {adapter!r}")
        endpoint = raw.get("endpoint") or ""
        path = raw.get("path") or ""
        if adapter == "http" and not isinstance(endpoint, str):
            _fail("ledger.endpoint must be a string")
        if adapter == "http" and endpoint:
            _check_placeholders(endpoint, "ledger.endpoint")
        if adapter == "fixture" and not path:
            _fail("ledger.adapter=fixture requires ledger.path")
        mapping = raw.get("map") or {}
        item_map = raw.get("item_map") or {}
        for label, value in (("map", mapping), ("item_map", item_map)):
            if not isinstance(value, Mapping) or not all(
                isinstance(k, str) and isinstance(v, str) for k, v in value.items()
            ):
                _fail(f"ledger.{label} must be an object of string -> string")
        return cls(
            adapter=adapter,
            endpoint=str(endpoint),
            path=str(path),
            map=dict(mapping),
            item_map=dict(item_map),
            id_field=str(raw.get("id_field") or "bookingId"),
        )


@dataclass(frozen=True)
class BolaSpec:
    """Which templates are *not* worth a cross-tenant replay.

    The mock ships legacy routes under ``/v1/`` that are covered by the exposure test
    instead, so the default filters them.  A target whose real API lives under
    ``/v2/`` must override this -- otherwise a heuristic tuned to the mock quietly
    excludes the entire real estate.
    """

    exclude_templates: tuple[str, ...] = ("/v1/", "/v2/", "/old/", "/test/")
    max_targets_per_id: int = 3

    def to_dict(self) -> dict[str, Any]:
        return {
            "exclude_templates": list(self.exclude_templates),
            "max_targets_per_id": self.max_targets_per_id,
        }

    @classmethod
    def parse(cls, raw: Any) -> "BolaSpec":
        if raw is None:
            return cls()
        if not isinstance(raw, Mapping):
            _fail("bola must be an object")
        _check_keys(raw, _BOLA_KEYS, "bola")
        limit = raw.get("max_targets_per_id", cls.max_targets_per_id)
        if not isinstance(limit, int) or limit < 1:
            _fail("bola.max_targets_per_id must be a positive integer")
        return cls(
            exclude_templates=_str_list(raw.get("exclude_templates"), "bola.exclude_templates"),
            max_targets_per_id=limit,
        )


@dataclass(frozen=True)
class BundleSpec:
    """Which path prefixes an API lives under.

    Bundle harvesting originally accepted only ``/api/...``, so a platform whose real
    routes start at ``/v2/...`` contributed nothing to the inventory -- and every route
    then looked undocumented.  The prefix is a property of the target.
    """

    route_prefixes: tuple[str, ...] = ("/api/",)

    def to_dict(self) -> dict[str, Any]:
        return {"route_prefixes": list(self.route_prefixes)}

    @classmethod
    def parse(cls, raw: Any) -> "BundleSpec":
        if raw is None:
            return cls()
        if not isinstance(raw, Mapping):
            _fail("bundle must be an object")
        _check_keys(raw, _BUNDLE_KEYS, "bundle")
        prefixes = _str_list(raw.get("route_prefixes"), "bundle.route_prefixes") or cls.route_prefixes
        for prefix in prefixes:
            if not prefix.startswith("/"):
                _fail(f"bundle.route_prefixes entries must start with '/': {prefix!r}")
        return cls(route_prefixes=prefixes)


# --------------------------------------------------------------------------------------
# the profile
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class TargetProfile:
    name: str = "mock-travel-api"
    description: str = ""
    flows: FlowProfile = field(default_factory=FlowProfile)
    identifiers: IdentifierSpec = field(default_factory=IdentifierSpec)
    agency: AgencySpec = field(default_factory=AgencySpec)
    ledger: LedgerSpec = field(default_factory=LedgerSpec)
    bola: BolaSpec = field(default_factory=BolaSpec)
    bundle: BundleSpec = field(default_factory=BundleSpec)
    source: str = "<built-in>"

    # -- construction ---------------------------------------------------------------

    @classmethod
    def load(cls, path: str | Path) -> "TargetProfile":
        p = Path(path)
        try:
            raw = json.loads(p.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise DastError(f"profile file not found: {p}") from exc
        except json.JSONDecodeError as exc:
            raise DastError(f"profile file is not valid JSON ({p}): {exc}") from exc
        if not isinstance(raw, dict):
            raise DastError(f"profile file must contain a JSON object: {p}")
        return cls.from_mapping(raw, source=str(p))

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any], *, source: str = "<dict>") -> "TargetProfile":
        if not isinstance(raw, Mapping):
            _fail(f"{source} must be an object")
        _check_keys(raw, _TOP_KEYS, source)

        ledger = LedgerSpec.parse(raw.get("ledger"))

        name = raw.get("name")
        if name is not None and not isinstance(name, str):
            _fail("name must be a string")

        return cls(
            name=name or "unnamed-target",
            description=str(raw.get("description") or ""),
            flows=FlowProfile.parse(raw.get("flows")),
            identifiers=IdentifierSpec.parse(raw.get("identifiers")),
            agency=AgencySpec.parse(raw.get("agency")),
            ledger=ledger,
            bola=BolaSpec.parse(raw.get("bola")),
            bundle=BundleSpec.parse(raw.get("bundle")),
            source=source,
        )

    @classmethod
    def mock_defaults(cls) -> "TargetProfile":
        """Exactly the vocabulary version 1 hard-coded, expressed as data.

        This is what a scope with no ``profile`` key gets, which is why adding the
        profile layer changes nothing about the bundled run.
        """
        return cls.from_mapping(
            {
                "name": "mock-travel-api",
                "description": "The bundled deliberately-vulnerable target (/api/...).",
                "flows": {
                    "hold": {"path": "/api/hold", "body": {"pax": "{pax}", "amount": "{amount}"}, "id_from": "bookingId"},
                    "pay": {"path": "/api/pay", "body": {"booking": "{id}", "amount": "{amount}"}},
                    "confirm": {"path": "/api/confirm", "body": {"booking": "{id}"}},
                    "cancel": {"path": "/api/cancel", "body": {"booking": "{id}"}},
                    "refund": {"path": "/api/refund", "body": {"booking": "{id}", "amount": "{amount}"}},
                    "rebook": {"path": "/api/rebook", "body": {"booking": "{id}", "amount": "{tampered}"}},
                    "ledger": {"path": "/api/ledger/{id}", "method": "GET"},
                },
                "identifiers": {"identity_field": "bookingId", "boundary_field": "agencyId"},
                "agency": {"probe_paths": ["/api/bookings", "/api/booking", "/api/me", "/api/agency/me"]},
                "ledger": {"adapter": "http", "endpoint": "/api/ledger/{id}"},
                "bola": {"exclude_templates": ["/v1/", "/v2/", "/old/", "/test/"]},
            },
            source="<mock-defaults>",
        )

    # -- reporting ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "source": self.source,
            "flows": {name: step.to_dict() for name, step in self.flows.steps.items()},
            "identifiers": self.identifiers.to_dict(),
            "agency": self.agency.to_dict(),
            "ledger": self.ledger.to_dict(),
            "bola": self.bola.to_dict(),
            "bundle": self.bundle.to_dict(),
        }

    def summarize(self) -> str:
        steps = ", ".join(sorted(self.flows.steps)) or "none"
        return (
            f"profile {self.name} ({self.source}): flows [{steps}]; "
            f"identity {self.identifiers.identity_field!r} / boundary "
            f"{self.identifiers.boundary_field!r}; ledger {self.ledger.adapter}"
            + (f" {self.ledger.endpoint}" if self.ledger.adapter == "http" else "")
        )
