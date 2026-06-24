# Phase D — Server-Side Enrichment (no client JS)

> Status: design (pending approval)
> Date: 2026-06-24
> Phase: D (of A→B→C→D roadmap)

## Goal

Add three new server-side data vectors computed from request headers / client IP,
stored under `data["_server<Name>"]` (mirroring the existing `_serverTransport` /
`_serverCveMatches` / `_serverRequest` pattern), rendered by new `_build_*_field`
functions in `surveillance_embeds.py`. Zero client-JS changes.

## Existing Pattern (contract to mirror)

```
extract_device_info(request)          → device_info dict (headers parsed once)
build_transport_profile(device_info)  → data["_serverTransport"]
build_request_profile(device_info)   → data["_serverRequest"]
lookup_browser_cves(device_info,data) → data["_serverCveMatches"]
                                      all called in send_advanced_data_to_discord()
```

Each builder returns a dict; embed renderer in `surveillance_embeds.py` reads the
`_server*` key via `data.get("_server<Name>")` and returns a field dict or `None`.
Field insertion happens in `create_combined_surveillance_embed` after the existing
`_build_transport_field` / `_build_cve_field` block (around line 419).

`ip_locator.py` reference pattern for local-DB modules:
- module-level globals (`_ranges_v4`, `_starts_v4`, `_db_loaded`)
- `set_logger(logger)` — logger injected from main.py
- `_load_db()` — lazy, idempotent (`if _db_loaded: return`), downloads CSV if stale
- `_binary_search(ip_int, ranges, starts)` — `bisect_right` lookup
- `_ensure_files()` / `_file_is_stale()` / `_download()` — download + refresh (7-day TTL)
- CSV source: `https://raw.githubusercontent.com/sapics/ip-location-db/main/...`
- Data dir: `os.path.join(os.path.dirname(__file__), "ipdb")`
- Loaded at startup in `main.py __main__` block AND lazily in `get_country()`

---

## Vector 1 — ASN / Hosting Organization

### Source

Local **dbip-asn** CSV from the **same GitHub repo** already used for country
lookup (`sapics/ip-location-db`), NOT MaxMind GeoLite2.

**Recommendation: local dbip-asn CSV (option a).**

Reasoning:
- The project already ships a local country DB using this exact repo + CSV
  loader + binary-search pattern. `asn_lookup.py` is a near-identical mirror
  (4-column CSV instead of 3-column) — zero new dependencies, zero new
  download infra, zero API key.
- MaxMind GeoLite2 ASN requires a **license key** (free account, but key must
  be distributed/managed as a secret). dbip-asn is **CC-BY-4.0**, no key.
- RDAP (option b) adds per-request HTTP latency (50–300 ms), an external
  dependency, rate limits, and a failure mode to handle on every request —
  all for data that a local DB returns in microseconds. RDAP is also less
  reliable for ASN attribution (varies by RIR).
- Offline-first matches the existing architecture: the country DB and VPN
  subnet list both download-once-then-cache. ASN should behave identically.

### Method

New module `asn_lookup.py`, structure mirrors `ip_locator.py`:

```python
# CSV URLs (same repo, asn subdirectory)
ASN_IPV4_URL = "https://raw.githubusercontent.com/sapics/ip-location-db/main/dbip-asn/dbip-asn-ipv4.csv"
ASN_IPV6_URL = "https://raw.githubusercontent.com/sapics/ip-location-db/main/dbip-asn/dbip-asn-ipv6.csv"

# Data dir: same ipdb/ dir as country DB
ASN_IPV4_PATH = os.path.join(DATA_DIR, "dbip-asn-ipv4.csv")
ASN_IPV6_PATH = os.path.join(DATA_DIR, "dbip-asn-ipv6.csv")
```

CSV format (4 columns, vs country's 3):
```
1.0.0.0,1.0.0.255,AS13335,"Cloudflare, Inc."
```

Module structure (identical to ip_locator.py):
- `set_logger(logger)` — injected from main.py
- `_load_db()` — lazy + idempotent, `_ensure_files()` + `_load_csv()`, sort, build
  `_starts` index, set `_db_loaded = True`
- `_load_csv(path, is_v4)` — parse 4-col rows into `(start_int, end_int, asn, org)` tuples
- `_binary_search(ip_int, ranges, starts)` — same `bisect_right` logic
- `lookup_asn(ip_address: str) -> dict | None` — public entry point, mirrors `get_country()`

Lazy init: called at startup in `__main__` block (alongside `_load_db()` for
country) AND lazily on first lookup (same dual-init as `get_country()`).

### Data shape

```python
{
    "asn": "AS13335",               # normalized "AS" + number
    "number": 13335,                 # int for comparison
    "organization": "Cloudflare, Inc.",
    "network": "1.0.0.0/24",        # CIDR of matched range (start/end → ip_network)
    "ipVersion": 4,                  # 4 or 6
}
```

Returns `None` if IP not found / invalid / DB not loaded.

### Render field

`_build_asn_field(data)` in `surveillance_embeds.py`:

```
🏢 ASN / Hosting
• ASN: `AS13335` · Org: `Cloudflare, Inc.`
• Network: `1.0.0.0/24`
• Classification: ☁️ Datacenter/CDN
```

Classification heuristic (curated ASN prefixes → type):
- `AS13335` (Cloudflare), `AS15169` (Google), `AS16509` (AWS),
  `AS8075` (Microsoft), `AS14618` (Amazon), `AS15169` (Google) → `☁️ Datacenter/CDN`
- Known VPN/hosting ASNs (overlap with existing VPN subnet list) → `🛡️ VPN/Hosting`
- Everything else → `🏠 Residential ISP`

This curated set is a small dict in `asn_lookup.py` (≤30 entries), same spirit as
`cve_lookup.py`'s curated catalogue. No external dependency.

### Latency

~microseconds (in-memory binary search). First call triggers CSV download
(~2–5 MB, same as country DB). Subsequent calls are instant.

### External dependency

dbip-asn CSV (CC-BY-4.0, no license key). Downloaded to `ipdb/`, 7-day refresh
TTL (same as country DB). If download fails → `lookup_asn` returns `None`,
field is silently omitted (graceful — matches `lookup_browser_cves` ImportError
fallback).

### Why this matters

ASN reveals the hosting organization behind an IP. Datacenter/CDN ASNs
(Cloudflare, AWS, DigitalOcean) strongly indicate **automated traffic, bots,
or proxy/VPN** — a real human on a residential connection would show a
consumer ISP ASN (Comcast, Vodafone, etc.). This pairs with the existing VPN
subnet check: a hit on both ASN + subnet = high-confidence automated traffic.
In the showcase: *"your ISP identity is visible to every website you visit,
and it betrays whether you're on a real connection or hiding behind a
hosting provider."*

---

## Vector 2 — Protocol / Connection Posture

### Source

Request headers already in `device_info`: `x_forwarded_for`, `x_forwarded_proto`,
`cf_visitor`, `cf_ray`, `scheme`, `x_real_ip`, `cf_connecting_ip`.

### Method

New function `build_protocol_posture(device_info)` in `main.py` (alongside
`build_transport_profile` / `build_request_profile`). Pure header derivation,
no external dependency, no I/O.

### Honest limitation (must be stated in code comment)

The app runs **behind nginx proxy manager** (see `proxy.conf`: `proxy_pass http://127.0.0.1:5002`).
nginx terminates TLS and downgrades to HTTP/1.1 for the upstream. **The app
cannot see the client's actual TLS version or HTTP/2-3 version.** Cloudflare
free tier does **not** expose JA3/JA4 fingerprints or TLS version in headers.
`CF-Visitor` only carries `{"scheme": "https"}` — not TLS version.

Therefore this vector computes **connection posture** (what IS obtainable), not
TLS fingerprinting. It does not claim JA3.

### Metrics computed

1. **Proxy chain depth** — count commas in `X-Forwarded-For` + 1. 1 = direct,
   2+ = proxied. Deep chains suggest proxy chains / Tor / VPN nesting.
2. **Protocol consistency** — do `scheme`, `X-Forwarded-Proto`, and
   `CF-Visitor.scheme` all agree? Mismatch = misconfigured proxy or HTTP→HTTPS
   downgrade attack surface.
3. **Cloudflare edge** — `CF-Ray` present → traffic routed through Cloudflare
   edge (implies HTTP/2 or HTTP/3 at edge, but app can't confirm which).
4. **Client-IP source** — which header yielded the IP (`CF-Connecting-IP` vs
   `X-Real-IP` vs `remote_addr`) — reveals trust chain.
5. **Forwarded-For consistency** — does the first XFF hop match the real IP?

### Data shape

```python
{
    "proxyChainDepth": 2,
    "cloudflareEdge": True,
    "cfRay": "89abc123def",
    "protoConsistency": True,       # scheme == forwardedProto == cfScheme
    "schemeObserved": "https",
    "ipSource": "CF-Connecting-IP",  # which header won
    "xffConsistent": True,          # first XFF hop == real_ip
}
```

Returns `{}` (empty → field omitted) if no device_info.

### Render field

`_build_protocol_field(data)` in `surveillance_embeds.py`:

```
🔌 Protocol Posture
• HTTPS: ✅ · Scheme: `https`
• Cloudflare edge: ✅ (Ray `89abc123def`)
• Proxy chain depth: `2` hop(s)
• Protocol consistency: ✅ all agree
• IP source: `CF-Connecting-IP`
```

If inconsistency: `⚠️ scheme/proto mismatch — possible downgrade`.
If proxyChainDepth > 2: `⚠️ deep proxy chain — possible Tor/VPN nesting`.

### Latency

~microseconds (string parsing). No I/O.

### External dependency

None.

### Why this matters

Shows whether the connection is secure (HTTPS end-to-end), whether traffic
passes through a CDN edge, and whether the proxy chain is suspiciously deep.
A mismatched scheme or deep chain suggests an insecure or anonymized
connection. In the showcase: *"every website can see how you're connecting
— whether your traffic is encrypted, how many proxies you're behind, and
whether your IP source is trustworthy."*

---

## Vector 3 — Accept-Language Profile

### Source

`device_info["accept_language"]` (already collected in `extract_device_info`).

### Method

New function `build_language_profile(device_info)` in `main.py`. Pure string
parsing of the `Accept-Language` header. No external dependency, no I/O.

Parses standard format: `en-US,en;q=0.9,de;q=0.8,ru;q=0.5`

1. **Primary language-tag** — first entry (highest q, usually q=1.0).
2. **Language list** — all tags with their q-values, sorted by q desc.
3. **Primary language** — subtag before `-` (e.g. `en` from `en-US`).
4. **Region** — subtag after `-` (e.g. `US` from `en-US`), uppercased.
5. **Script** — 4-letter subtag if present (e.g. `Hant` from `zh-Hant`).
6. **Entropy bits** — Shannon entropy of the q-list (more languages / even
   q-values = higher entropy = more multilingual/anomalous setup).
7. **Mismatch flag** — does the primary language region conflict with the
   GeoIP country code (e.g. `Accept-Language: ru` but GeoIP says `US`)?

### Data shape

```python
{
    "primary": "en-US",
    "primaryLanguage": "en",
    "region": "US",
    "script": None,
    "languages": [
        {"tag": "en-US", "q": 1.0},
        {"tag": "en", "q": 0.9},
        {"tag": "de", "q": 0.8},
        {"tag": "ru", "q": 0.5},
    ],
    "count": 4,
    "entropyBits": 1.86,
    "geoMismatch": False,       # requires country_code passed in
}
```

Returns `{}` if `accept_language` is "Unknown"/missing.

### Render field

`_build_language_field(data)` in `surveillance_embeds.py`:

```
🗣️ Language Profile
• Primary: `en-US` (en · US)
• Languages: `en-US` (q=1.0), `en` (q=0.9), `de` (q=0.8), `ru` (q=0.5)
• Entropy: `1.86 bits` (multilingual)
• Geo mismatch: ✅ consistent
```

If geoMismatch: `⚠️ language/geo mismatch — primary `ru` but IP is `US``.

### Latency

~microseconds (string parsing). No I/O.

### External dependency

None. (Geo mismatch check uses the country code already resolved by
`get_country()` — passed into the builder, not a new lookup.)

### Why this matters

`Accept-Language` reveals the user's preferred language and region — a
social-engineering signal. A user claiming to be US-based but with
`ru,en;q=0.9` as their primary language is suspicious. Multilingual setups
(entropy) correlate with tech-savvy or non-native users. In the showcase:
*"your language preferences are broadcast to every site — they reveal your
native tongue, your region, and whether you're pretending to be somewhere
you're not."*

---

## Wiring

### `main.py` — `send_advanced_data_to_discord()` (extend existing block)

```python
if isinstance(data, dict):
    # ... existing transport / request / cve enrichment ...

    asn_info = lookup_asn(ip_address)          # NEW — needs IP, not device_info
    if asn_info:
        data["_serverAsn"] = asn_info

    protocol_posture = build_protocol_posture(device_info)   # NEW
    if protocol_posture:
        data["_serverProtocol"] = protocol_posture

    lang_profile = build_language_profile(device_info, country_code2)  # NEW
    if lang_profile:
        data["_serverLanguage"] = lang_profile
```

Note: ASN lookup needs `ip_address` (already a parameter of
`send_advanced_data_to_discord`). Language profile's geo-mismatch check needs
the country code — available from `device_info` via the CF-IPCountry header
(`device_info["cf_ipcountry"]`) or a `get_country(ip_address)` call. Prefer
the header (zero-latency) with GeoIP fallback.

### `main.py` — `__main__` startup block (extend existing preload)

```python
# Preload ASN database at startup (mirrors GeoIP preload)
try:
    from asn_lookup import _load_db as _load_asn_db
    _load_asn_db()
    l.passing("ASN database loaded successfully")
except Exception as e:
    l.error(f"Failed to load ASN database: {e}")
    l.warning("ASN lookup may be delayed on first request")
```

### `main.py` — imports

```python
from asn_lookup import lookup_asn, set_logger as set_asn_logger
```
And in `__main__`: `set_asn_logger(l)` (mirrors `set_logger(l)` for ip_locator).

### `surveillance_embeds.py` — new field builders + insertion

Three new functions:
- `_build_asn_field(data)` — reads `data["_serverAsn"]`
- `_build_protocol_field(data)` — reads `data["_serverProtocol"]`
- `_build_language_field(data)` — reads `data["_serverLanguage"]`

Inserted in `create_combined_surveillance_embed` after the existing
`_build_cve_field` block (line ~419), before the risk assessment:

```python
# ---- Server-side ASN / hosting ----
asn_field = _build_asn_field(data)
if asn_field:
    embed["fields"].append(asn_field)

# ---- Server-side protocol posture ----
protocol_field = _build_protocol_field(data)
if protocol_field:
    embed["fields"].append(protocol_field)

# ---- Server-side language profile ----
language_field = _build_language_field(data)
if language_field:
    embed["fields"].append(language_field)
```

### `surveillance_embeds.py` — risk assessment integration

Extend `_build_risk_assessment` to score the new vectors:
- Datacenter/CDN ASN → +15 risk, factor "Datacenter/hosting ASN detected"
- Protocol inconsistency → +10, "Protocol scheme mismatch"
- Proxy chain depth > 2 → +10, "Deep proxy chain"
- Language/geo mismatch → +15, "Language/geo mismatch"

---

## New files

| File | Purpose |
|------|---------|
| `asn_lookup.py` | ASN module mirroring `ip_locator.py` (set_logger, _load_db, _binary_search, lookup_asn) |

## Edited files

| File | Changes |
|------|---------|
| `main.py` | `build_protocol_posture()`, `build_language_profile()`, `lookup_asn` import, wire 3 vectors in `send_advanced_data_to_discord`, preload ASN DB in `__main__` |
| `surveillance_embeds.py` | `_build_asn_field()`, `_build_protocol_field()`, `_build_language_field()`, insertion in `create_combined_surveillance_embed`, risk-assessment scoring |

## Files NOT touched

- `static/js/advanced-collection.js` — no client JS (Phase D is server-only)
- `templates/result.html`
- `ip_locator.py` — ASN module is separate, not a patch to country module
- `cve_lookup.py`

## Tests

No existing test for `_build_transport_field` / `_build_cve_field`. Add:

1. `tests/test_asn_lookup.py` — unit test `lookup_asn()` with a tiny fixture CSV
   (2–3 rows, no network download). Assert correct ASN for an IP in range,
   `None` for IP out of range, `None` for invalid IP. Mirror
   `tests/test_surveillance_embeds.py` style.

2. `tests/test_surveillance_embeds.py` — add `TestServerSideFields` class:
   - Feed `{"_serverAsn": {...}}` → assert `_build_asn_field` renders + field name
   - Feed `{"_serverProtocol": {...}}` → assert `_build_protocol_field` renders
   - Feed `{"_serverLanguage": {...}}` → assert `_build_language_field` renders
   - Feed `{}` → assert all three return `None`
   - Feed `{"_serverAsn": {"asn": "AS13335", ...}}` → assert "Datacenter" classification

3. `tests/test_main.py` — add test for `build_language_profile()` parsing
   `en-US,en;q=0.9,de;q=0.8` → assert primary, region, count, entropy.

## Constraints satisfied

- ✅ New module `asn_lookup.py` mirrors `ip_locator.py` structure
- ✅ Wired in `send_advanced_data_to_discord` like existing `build_transport_profile`
- ✅ No client JS edits
- ✅ Does not break existing `_server*` enrichment (new keys, new functions)
- ✅ Offline-first (dbip-asn local CSV, no license key, mirrors country DB)
- ✅ No RDAP (chosen against — latency, dependency, rate limits)
- ✅ No JA3 / TLS version claim (honest about nginx-proxy limitation)
- ✅ Graceful failure (ASN returns `None` if DB missing → field omitted)

## Deferred (other phases)

- JA3/JA4 TLS fingerprinting — requires a TLS-terminating sidecar or
  Cloudflare Enterprise (not free tier). Out of scope.
- HTTP/2-3 client version — not visible behind nginx proxy. Would need
  edge-level inspection (Cloudflare Worker) or raw-socket listener.
- Phase A (client collectors) and Phase B/C — separate specs.
