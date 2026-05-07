"""
Passive browser CVE lookup.

Given a browser family + version (parsed from the User-Agent / UA-CH headers),
return the curated CVE entries that affect versions older than `fixed_in`.

This module is intentionally PASSIVE:
  - No exploit code.
  - No network calls; the curated list is small and ships with the repo.
  - Comparisons are dotted-version aware (semver-ish: ints split on '.').

Designed to be called server-side once per request after the UA is parsed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Optional


# ---------------------------------------------------------------------------
# Curated CVE catalogue.
#
# Each entry lists the *first fixed version* (`fixed_in`). Anything older than
# that is reported as vulnerable. Keep this list short and high-signal — it's
# meant to demonstrate "your browser is missing patch X", not be exhaustive.
#
# Source: Chromium / Mozilla / WebKit security release notes. CVSS scores are
# the published vendor or NVD scores at disclosure time.
# ---------------------------------------------------------------------------

_CATALOGUE: dict[str, list[dict]] = {
    "chrome": [
        {
            "id": "CVE-2025-2783",
            "fixed_in": "134.0.6998.177",
            "cvss": 8.3,
            "severity": "high",
            "summary": "Mojo IPC sandbox escape (in-the-wild).",
        },
        {
            "id": "CVE-2024-7971",
            "fixed_in": "128.0.6613.84",
            "cvss": 8.8,
            "severity": "high",
            "summary": "V8 type confusion (in-the-wild).",
        },
        {
            "id": "CVE-2024-4761",
            "fixed_in": "124.0.6367.207",
            "cvss": 8.8,
            "severity": "high",
            "summary": "V8 out-of-bounds write (in-the-wild).",
        },
        {
            "id": "CVE-2024-4671",
            "fixed_in": "124.0.6367.201",
            "cvss": 8.8,
            "severity": "high",
            "summary": "Visuals use-after-free (in-the-wild).",
        },
        {
            "id": "CVE-2024-0519",
            "fixed_in": "120.0.6099.234",
            "cvss": 8.8,
            "severity": "high",
            "summary": "V8 out-of-bounds memory access (in-the-wild).",
        },
        {
            "id": "CVE-2023-7024",
            "fixed_in": "120.0.6099.129",
            "cvss": 8.8,
            "severity": "high",
            "summary": "WebRTC heap buffer overflow (in-the-wild).",
        },
        {
            "id": "CVE-2023-6345",
            "fixed_in": "119.0.6045.199",
            "cvss": 9.6,
            "severity": "critical",
            "summary": "Skia integer overflow (in-the-wild).",
        },
    ],
    "firefox": [
        {
            "id": "CVE-2024-9680",
            "fixed_in": "131.0.2",
            "cvss": 9.8,
            "severity": "critical",
            "summary": "Animation timeline use-after-free (in-the-wild).",
        },
        {
            "id": "CVE-2024-29943",
            "fixed_in": "124.0.1",
            "cvss": 9.8,
            "severity": "critical",
            "summary": "Range-analysis OOB read/write at Pwn2Own.",
        },
        {
            "id": "CVE-2024-29944",
            "fixed_in": "124.0.1",
            "cvss": 9.8,
            "severity": "critical",
            "summary": "Privileged JS event-handler escape at Pwn2Own.",
        },
        {
            "id": "CVE-2023-4863",
            "fixed_in": "117.0.1",
            "cvss": 8.8,
            "severity": "high",
            "summary": "libwebp heap buffer overflow (BLASTPASS).",
        },
    ],
    "safari": [
        {
            "id": "CVE-2025-24201",
            "fixed_in": "18.3.1",
            "cvss": 7.1,
            "severity": "high",
            "summary": "WebKit out-of-bounds write (in-the-wild).",
        },
        {
            "id": "CVE-2024-44308",
            "fixed_in": "18.1.1",
            "cvss": 8.8,
            "severity": "high",
            "summary": "JavaScriptCore RCE (in-the-wild).",
        },
        {
            "id": "CVE-2024-44309",
            "fixed_in": "18.1.1",
            "cvss": 6.1,
            "severity": "medium",
            "summary": "WebKit cookie management XSS (in-the-wild).",
        },
        {
            "id": "CVE-2023-37450",
            "fixed_in": "16.5.2",
            "cvss": 8.8,
            "severity": "high",
            "summary": "WebKit RCE (rapid security response).",
        },
    ],
    "edge": [
        # Edge tracks Chromium fixed_in versions.
        {
            "id": "CVE-2025-2783",
            "fixed_in": "134.0.3124.93",
            "cvss": 8.3,
            "severity": "high",
            "summary": "Chromium Mojo IPC sandbox escape carry-over.",
        },
        {
            "id": "CVE-2024-7971",
            "fixed_in": "128.0.2739.42",
            "cvss": 8.8,
            "severity": "high",
            "summary": "Chromium V8 type confusion carry-over.",
        },
    ],
    "opera": [
        {
            "id": "CVE-2024-7971",
            "fixed_in": "113.0.5230.0",
            "cvss": 8.8,
            "severity": "high",
            "summary": "Chromium V8 type confusion carry-over.",
        },
    ],
}


# Map common UA family strings → catalogue keys.
_FAMILY_ALIASES = {
    "chrome": "chrome",
    "chrome mobile": "chrome",
    "chrome mobile webview": "chrome",
    "chromium": "chrome",
    "google chrome": "chrome",
    "firefox": "firefox",
    "firefox mobile": "firefox",
    "mozilla firefox": "firefox",
    "safari": "safari",
    "mobile safari": "safari",
    "edge": "edge",
    "edge mobile": "edge",
    "microsoft edge": "edge",
    "opera": "opera",
    "opera mobile": "opera",
    "opera mini": "opera",
}


@dataclass(frozen=True)
class CVEMatch:
    id: str
    cvss: float
    severity: str
    summary: str
    fixed_in: str

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "cvss": self.cvss,
            "severity": self.severity,
            "summary": self.summary,
            "fixed_in": self.fixed_in,
        }


def _normalize_family(family: Optional[str]) -> Optional[str]:
    if not family:
        return None
    return _FAMILY_ALIASES.get(family.strip().lower())


def _parse_version(version: Optional[str]) -> Optional[tuple[int, ...]]:
    """Parse 'X.Y.Z[.W]' into a tuple of ints. Returns None on failure."""
    if not version or version == "Unknown":
        return None
    parts: list[int] = []
    for chunk in version.strip().split("."):
        digits = "".join(c for c in chunk if c.isdigit())
        if not digits:
            break
        try:
            parts.append(int(digits))
        except ValueError:
            break
    return tuple(parts) if parts else None


def _is_older(actual: tuple[int, ...], threshold: tuple[int, ...]) -> bool:
    """Return True if actual < threshold under tuple comparison with zero-pad."""
    length = max(len(actual), len(threshold))
    a = actual + (0,) * (length - len(actual))
    t = threshold + (0,) * (length - len(threshold))
    return a < t


def lookup_cves(family: Optional[str], version: Optional[str]) -> List[CVEMatch]:
    """Return CVEs for which `version` is older than the entry's `fixed_in`."""
    key = _normalize_family(family)
    if not key:
        return []

    actual = _parse_version(version)
    if not actual:
        return []

    matches: list[CVEMatch] = []
    for entry in _CATALOGUE.get(key, []):
        threshold = _parse_version(entry["fixed_in"])
        if not threshold:
            continue
        if _is_older(actual, threshold):
            matches.append(
                CVEMatch(
                    id=entry["id"],
                    cvss=float(entry["cvss"]),
                    severity=entry["severity"],
                    summary=entry["summary"],
                    fixed_in=entry["fixed_in"],
                )
            )

    matches.sort(key=lambda m: m.cvss, reverse=True)
    return matches


def summarise(matches: Iterable[CVEMatch]) -> dict:
    """Aggregate a list of CVE matches for compact display."""
    matches = list(matches)
    if not matches:
        return {"count": 0, "max_cvss": 0.0, "highest_severity": "none", "items": []}
    max_cvss = max(m.cvss for m in matches)
    rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}
    highest = max(matches, key=lambda m: rank.get(m.severity, 0)).severity
    return {
        "count": len(matches),
        "max_cvss": max_cvss,
        "highest_severity": highest,
        "items": [m.to_dict() for m in matches],
    }
