# Phase A — Wire 11 Missing Client Collectors

> Status: approved (silent-only constraint confirmed)
> Date: 2026-06-24

## Goal

`surveillance_embeds.py` already renders embed fields for 11 data vectors, but
`static/js/advanced-collection.js` never collects them — the fields are empty in
every report. Wire the 11 collectors so the existing display code lights up.

## Constraint

**100% silent.** No permission prompt, no user gesture, no dialog. This matches
the educational thesis: *"any ordinary website silently learns this."*
`getScreenDetails()` (gesture-gated) is deferred to a later phase.

## Vectors (the 11)

| # | key | method | notes |
|---|-----|--------|-------|
| 1 | `uaClientHints` | `navigator.userAgentData.getHighEntropyValues([...])` | Chromium-only; absence = signal (FF/Safari leak less) |
| 2 | `webgpu` | `navigator.gpu.requestAdapter()` → `.info` / `requestAdapterInfo()` | async, no perm |
| 3 | `drm` | `requestMediaKeySystemAccess` for Widevine/PlayReady/FairPlay + `MediaCapabilities.decodingInfo` for H264/VP9/AV1/HEVC/EAC3 | FairPlay=Apple, PlayReady=Win/Edge → OS leak |
| 4 | `speechVoices` | `speechSynthesis.getVoices()` + `voiceschanged` wait | voices load async |
| 5 | `keyboardLayout` | `navigator.keyboard.getLayoutMap()` | secure ctx only; sample subset |
| 6 | `installedApps` | `navigator.getInstalledRelatedApps()` | Chrome-Android PWA mainly |
| 7 | `screenDetails` | `screen.isExtended` only (silent) | getScreenDetails deferred |
| 8 | `hardeningSignals` | `crossOriginIsolated`, `isSecureContext`, `SharedArrayBuffer` feature-detect, `trustedTypes`, `cookieStore`, `storageAccessApi` | all passive |
| 9 | `mediaQueries` | `matchMedia` set: color-scheme, reduced-motion, reduced-transparency, contrast, forced-colors, inverted-colors, color-gamut, dynamic-range, reduced-data, hover, any-pointer | passive |
| 10 | `permissions` | `navigator.permissions.query({name})` for geolocation/notifications/camera/microphone/persistent-storage/background-sync/storage-access/clipboard-read/midi/window-management | each try/catch (some throw on unsupported) |
| 11 | `navigationTiming` | `performance.getEntriesByType('navigation')[0]` → responseStart/loadEventEnd/transferSize/domInteractive/type | passive |

## Data Contract (must match existing builders)

Each collector sets `this.collectedData.<key>` to either:
- a populated dict (rendered by `_is_valid_dict` → field shows), or
- `{ "error": "<msg>" }` (skipped by `_is_valid_dict` → field hidden).

Add a `safe(fn, fallback)` wrapper + `supports(obj, ...path)` feature-detect to
kill try/catch boilerplate.

## Files

- **Edit:** `static/js/advanced-collection.js` — add 11 `collectX()` methods,
  call them in `init()` via `Promise.allSettled` batch (not sequential awaits).
  Extend the existing `sendData()` POST body — no new endpoint.
- **Do NOT edit:** `surveillance_embeds.py` (fields already exist),
  `main.py`, `templates/`.

## Tests

No JS test infra. Add Python test in `tests/test_surveillance_embeds.py`:
feed sample dicts for each of the 11 keys → assert the matching embed field
renders (e.g. `uaClientHints` → "UA-CH High Entropy" field present).

## Deferred (other phases)

`getScreenDetails()` gesture-gated multi-monitor → Phase B+. ASN/TLS server-side
→ Phase D. New no-permission vectors (webdriver, Intl, GPC, …) → Phase B.
