# Phase A Implementation Result

## Summary

Wired the 11 missing client-side collectors into `static/js/advanced-collection.js`.
All 11 keys were already expected by field builders in `surveillance_embeds.py` —
the data was never sent, so the embed fields were always empty. Now they light up.

## Methods Added (11)

| # | key | method | data shape | field rendered |
|---|-----|--------|------------|----------------|
| 1 | `uaClientHints` | `collectUAClientHints()` | `{brands, fullVersionList, platform, platformVersion, architecture, bitness, model, mobile, formFactor}` | 🪪 UA-CH High Entropy |
| 2 | `webgpu` | `collectWebGPU()` | `{vendor, architecture, device}` | 🚀 Hardware Acceleration |
| 3 | `drm` | `collectDRM()` | `{keySystems: {Widevine,PlayReady,FairPlay}, codecs: {H.264,VP9,AV1,HEVC,EAC3}}` | 🚀 Hardware Acceleration |
| 4 | `speechVoices` | `collectSpeechVoices()` | `{count, sample: [{name,lang}]}` | 🕵️ OS-Level Leaks |
| 5 | `keyboardLayout` | `collectKeyboardLayout()` | `{size, sample: {key→value}}` | 🧭 Display & Input Capabilities |
| 6 | `installedApps` | `collectInstalledApps()` | `{count, apps: [{id,platform}]}` | 🕵️ OS-Level Leaks |
| 7 | `screenDetails` | `collectScreenDetails()` | `{isExtended: bool}` | 🧭 Display & Input Capabilities |
| 8 | `hardeningSignals` | `collectHardeningSignals()` | `{sharedArrayBuffer, crossOriginIsolated, isSecureContext, trustedTypes, cookieStore, storageAccessApi}` | 🛡️ Hardening Posture |
| 9 | `mediaQueries` | `collectMediaQueries()` | `{colorSchemeDark, reducedMotion, …} (bool per probe)` | 🧭 Display & Input Capabilities |
| 10 | `permissions` | `collectPermissions()` | `{geolocation:"granted", …} (state string per name)` | 🔐 Permissions State |
| 11 | `navigationTiming` | `collectNavigationTiming()` | `{type, responseStart, loadEventEnd, transferSize, domInteractive}` | counted in 📌 Captured Vectors |

## Helpers Added

- `supports(obj, ...path)` — nested property feature-detect, returns bool, never throws
- `safe(fn, fallback)` — async try/catch wrapper, returns `fallback` (value or `fn(e)`) on error

## Wiring

All 11 collectors run via `Promise.allSettled([...])` batch in `init()`, placed after
the existing sequential collectors and before `sendData()`. Existing collectors are
untouched. `sendData()` requires no changes — it already posts `this.collectedData`
which now includes the 11 new keys.

## Constraints Met

- ✅ 100% silent: no permission prompt, no user gesture, no dialog
- ✅ `screenDetails`: `screen.isExtended` only — `getScreenDetails()` NOT called
- ✅ Each collector sets populated dict OR `{error: msg}` matching `_is_valid_dict`
- ✅ `safe()` + `supports()` helpers added
- ✅ 11 collectors in `Promise.allSettled` batch, not sequential awaits
- ✅ Existing collectors intact
- ✅ `sendData()` unchanged (data already flows through)
- ✅ No new endpoint, no template changes
- ✅ `surveillance_embeds.py` and `main.py` NOT edited

## Tests

22 new tests added to `tests/test_surveillance_embeds.py` under `TestPhaseACollectors`:
- One render test per key (asserts matching field name appears in embed)
- Error-skip tests for `uaClientHints`, `hardeningSignals`, `permissions`
- `navigationTiming` counted-in-vectors test (no dedicated field)
- `screenDetails` `isExtended: False` still renders
- Integration test: all 11 keys together → all expected fields render

## Final pytest Result

```
tests/test_surveillance_embeds.py: 64 passed
Full suite: 102 passed, 26 deselected in 0.72s
```

## Residual Risks

- `collectDRM()` calls `requestMediaKeySystemAccess` and `mediaCapabilities.decodingInfo`
  for each codec — this is 3 + 5 = 8 sequential async calls. Could be parallelized with
  `Promise.allSettled` inside the method if latency is a concern, but total runtime is
  typically <100ms and the collector is already batched in the outer `Promise.allSettled`.
- `collectSpeechVoices()` waits up to 1500ms for `voiceschanged` event on browsers where
  voices load async. This is within the outer `Promise.allSettled` so it doesn't block
  other collectors.
- `navigator.permissions.query({name})` throws for unsupported permission names on some
  browsers — each name is individually try/caught so one failure doesn't break the batch.
- No JS test infrastructure exists — shapes are verified indirectly via Python embed tests
  using sample dicts matching the `_is_valid_dict` contract.
