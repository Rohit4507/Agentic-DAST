"""SARIF 2.1.0 export.

Why bother: it makes the output CI-consumable (GitHub code scanning, or a `jq` gate),
and it is the format the reference implementations in the research pack (Shannon,
shadow-Audit) already emit — so the pipeline drops into an existing workflow instead of
inventing one.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from ..model import Finding

SARIF_VERSION = "2.1.0"
SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_NAME = "dast-agent"
TOOL_URI = "https://github.com/Rohit4507/Automated-Vulnerability-Scanning-with-Agentic-AI"

_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "informational": "note"}


def _rule_id(f: Finding) -> str:
    return f.vuln_class or "dast-finding"


def build_sarif(findings: Iterable[Finding], *, tool_version: str = "0.1.0") -> dict[str, Any]:
    findings = list(findings)
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for f in findings:
        rid = _rule_id(f)
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": rid,
                "shortDescription": {"text": f.vuln_class.replace("_", " ").capitalize()},
                "fullDescription": {
                    "text": f"{f.owasp} / {f.cwe}".strip(" /") or "Verified by deterministic validation"
                },
                "helpUri": "https://owasp.org/API-Security/editions/2023/en/0x11-t10/",
                "properties": {
                    "tags": ["security", "api", f.owasp.split()[0] if f.owasp else "OWASP"],
                    "precision": "high",
                },
                "defaultConfiguration": {"level": _LEVEL.get(f.severity, "warning")},
            }
        results.append(
            {
                "ruleId": rid,
                "level": _LEVEL.get(f.severity, "warning"),
                "message": {"text": f"{f.title} ({f.owasp}; {f.cwe})"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f"{f.method} {f.endpoint}",
                                "uriBaseId": "API",
                            },
                        },
                        "logicalLocations": [
                            {"fullyQualifiedName": f.endpoint, "kind": "function"}
                        ],
                    }
                ],
                "properties": {
                    "finding_id": f.id,
                    "severity": f.severity,
                    "business_score": f.cvss,
                    "severity_rationale": f.business_impact,
                    "confidence": f.confidence,
                    "owner": f.owner,
                    "cwe": f.cwe,
                    "proof_hash": f.proof_hash,
                    "retest_mode": (f.retest or {}).get("mode"),
                    "reproduce": (f.retest or {}).get("reproduce", ""),
                },
                "fingerprints": {"dast/v1": f.dedupe_key or f.proof_hash or f.id},
            }
        )

    return {
        "$schema": SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": tool_version,
                        "informationUri": TOOL_URI,
                        "rules": list(rules.values()),
                    }
                },
                "automationDetails": {"id": "dast-agent/run"},
                "results": results,
            }
        ],
    }


def write_sarif(path: str | Path, findings: Iterable[Finding], *, tool_version: str = "0.1.0") -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(build_sarif(findings, tool_version=tool_version), indent=2), encoding="utf-8")
    return p
