# Phase D Design Result — Server-Side Enrichment

**Spec written to:** `docs/pi/specs/2026-06-24-phaseD-server-side-design.md`

## 5-Line Summary

1. **ASN source recommendation: local dbip-asn CSV** (option a) — same `sapics/ip-location-db` GitHub repo already used for the country DB, CC-BY-4.0, no license key; new `asn_lookup.py` mirrors `ip_locator.py` exactly (set_logger, _load_db, _binary_search, lazy init). MaxMind GeoLite2 rejected (needs license key); RDAP rejected (latency, rate limits, dependency per-request).
2. **Protocol posture: honest about nginx-proxy limitation** — app behind nginx proxy manager, cannot see client TLS version or HTTP/2-3. Computes what IS obtainable: proxy chain depth, protocol consistency, Cloudflare edge presence, IP-source trust chain. No JA3 claim (not obtainable on free tier).
3. **Accept-Language profile: pure string parsing** of already-collected `device_info["accept_language"]` — primary language, region, q-list, Shannon entropy, geo-mismatch flag. Zero external dependency.
4. **Wiring mirrors existing pattern exactly** — three new builders called in `send_advanced_data_to_discord` alongside `build_transport_profile`/`lookup_browser_cves`, stored as `data["_serverAsn"]`/`["_serverProtocol"]`/`["_serverLanguage"]`, rendered by new `_build_*_field` functions in `surveillance_embeds.py` inserted after the existing CVE field block.
5. **No client JS, no existing _server* breakage** — new module + new functions + new keys only. Graceful failure (ASN returns None if DB missing → field omitted). Tests specified for all three vectors.

## Key Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| ASN data source | dbip-asn CSV (local) | Same repo/license/pattern as country DB; no key, no latency, offline-first |
| TLS version / JA3 | Not claimed | nginx proxy terminates TLS; Cloudflare free tier doesn't expose JA3 |
| Protocol posture scope | Connection posture only | Honest about what's obtainable behind nginx/CF |
| New module | `asn_lookup.py` | Mirrors `ip_locator.py` structure exactly |
| Language geo-mismatch | Uses CF-IPCountry header | Zero-latency; GeoIP fallback only if header absent |

## Files

| File | Action | Purpose |
|------|--------|---------|
| `asn_lookup.py` | NEW | ASN module mirroring ip_locator.py |
| `main.py` | EDIT | `build_protocol_posture()`, `build_language_profile()`, wire 3 vectors, preload ASN DB |
| `surveillance_embeds.py` | EDIT | 3 new `_build_*_field` functions, insertion, risk-scoring |
| `tests/test_asn_lookup.py` | NEW | Unit test lookup_asn with fixture CSV |
| `tests/test_surveillance_embeds.py` | EDIT | TestServerSideFields class |

## Residual Risks

1. **dbip-asn CSV size** — ASN DB is larger than country DB (~5-8 MB combined v4+v6 vs ~2 MB country). First download at startup adds latency. Mitigated by 7-day TTL cache + lazy init (already proven pattern).
2. **ASN classification heuristic** — the curated datacenter/CDN ASN list is small (~30 entries). New hosting providers won't be classified as datacenter until added. Acceptable for educational showcase; can expand over time.
3. **Protocol posture is not TLS fingerprinting** — may underwhelm users expecting JA3. The spec is explicit about this limitation. The "why this matters" framing compensates by focusing on proxy-chain and consistency signals that ARE obtainable.
4. **Language geo-mismatch false positives** — multilingual users legitimately have `de,en;q=0.9` while in US. The mismatch flag is a hint, not a verdict; risk score (+15) may need tuning after real-world testing.
