# Phase C — Real Behavioral Biometric Signals

> Status: design (awaiting approval — this is a spec, no code yet)
> Date: 2026-06-24
> Phase order: A (missing collectors) → **C (this)** — B/D are separate tracks

## Problem

`collectBehavioralData()` in `static/js/advanced-collection.js` declares five
arrays (`mouseMovements`, `clicks`, `scrolls`, `keypresses`, `touchEvents`) but
only `mouseMovements` gets up to 10 points; the other four stay **empty**. Focus
state is a one-shot snapshot, not a transition history. The Discord showcase
(`_build_advanced_fingerprinting`) therefore prints `Mouse events 0 · page
hidden` and nothing else — the "behavioral biometric" claim is hollow. Phase C
makes the claim real by actually capturing timing and trajectory signals.

## ⚠️ Hard Rule — No Key Content

**NEVER record keystroke content. Only timing (key-down timestamp, key-up
timestamp, inter-key gap).** No `e.key`, no `e.code`, no `e.keyCode`, no
`e.which`, no `input.value`. The listener attaches to `keydown`/`keyup` at the
`window` level and stores only numeric timing deltas. This rule is loud in the
code: a comment block on the handler and a guard that throws if any content
field is referenced. Any PR that touches `e.key` in this collector is rejected.

## Vectors (5 behavioral signals + session metadata)

| # | signal | capture method | data shape |
|---|--------|----------------|------------|
| 1 | Dwell time | `performance.now()` at DOMContentLoaded → flushed on `pagehide`/`visibilitychange=hidden` | `dwellMs: number` |
| 2 | Scroll depth | `scroll` listener → track `maxScrollPct` (capped calc) | `scroll: {maxScrollPct, events: n}` |
| 3 | Mouse trajectory | `mousemove` listener → store first **50** points `{x,y,t}` + running `totalMoves` count (kept after cap) | `mouseMovements: [{x,y,t}...]` (≤50), `mouseMoveCount: n` |
| 4 | Clicks | `click` listener → `{x,y,t,button}` capped at **25** | `clicks: [{...}]` (≤25), `clickCount: n` |
| 5 | Keystroke cadence | `keydown`/`keyup` at window → `{downMs, upMs, dwellMs, gapMs}` (timing ONLY) capped at **30 keystrokes** | `keystrokes: [{...}]` (≤30), `keystrokeCount: n` |
| 6 | Touch (mobile) | `touchstart` → `{x,y,t}` capped at **30** | `touchEvents: [{...}]` (≤30), `touchCount: n` |
| 7 | Visibility/focus transitions | `visibilitychange`+`blur`/`focus` → append `{state, t}` (capped at **20**) instead of snapshot | `visibilityTransitions: [{...}]` (≤20) |

### Sampling limits (bounded memory + payload)

- Mouse points ≤ 50, clicks ≤ 25, keystrokes ≤ 30, touches ≤ 30, visibility
  transitions ≤ 20. Total worst-case ≈ 155 small objects (~6 fields each) ≈ well
  under 20 KB. No unbounded arrays.
- Each handler self-removes its listener once the cap is hit (same pattern the
  current `mousemove` handler already uses) to stop CPU burn.
- Counts (`mouseMoveCount`, `clickCount`, `keystrokeCount`, `touchCount`) are
  **uncapped** integers — the total activity volume is the high-entropy signal,
  the capped arrays are just samples.

## Data Contract (matches existing `_is_valid_dict`)

`this.collectedData.behavioral` is set to either:
- a populated dict → `_build_behavioral_field` renders it, OR
- `{ "error": "<msg>" }` → skipped (field hidden), same as every other vector.

Existing keys (`pageVisible`, `hasFocus`, `tabVisibility`) are preserved for
backward compat with the current renderer + risk-assessment check
(`behavioral.mouseMovements` presence → +15). The new richer fields are
additive.

## Rendering (surveillance_embeds.py — append-only)

### New function: `_build_behavioral_field(data)`

Returns a dedicated **🖱️ BEHAVIORAL BIOMETRICS** field (inline: false). Fields
shown only when the underlying data exists (no empty bullets). Example layout:

```
🖱️ **BEHAVIORAL BIOMETRICS**
└ Dwell `4.2s` · max scroll `78%`
└ Mouse: `312` moves (50 sampled) · `4` clicks
└ Keystrokes: `28` (dwell μ `94ms` · gap μ `162ms`)  [timing only — no content]
└ Touch: `7` events
└ Focus: `hidden→visible→hidden` (3 transitions)
```

Aggregates computed in the builder: mean dwell, mean gap, transition sequence
string. No raw arrays dumped to Discord (would blow the 1024-char field limit).

### Existing `_build_advanced_fingerprinting` behavioral bullet

Left in place but simplified to a one-liner pointer ("see BEHAVIORAL
BIOMETRICS field") to avoid duplication. Its risk-assessment hook
(`behavioral.mouseMovements` → +15 score) is extended: real keystroke cadence
present → +10, dwell > 5s → +5 (capped). Keeps scoring coherent.

### "Why This Matters" framing

The behavioral field ends with a victim-facing line (reuse the Phase A
`_build_impact_field` pattern):

> _Behavioral biometrics re-identify you across sessions even after you clear
> cookies — your typing rhythm and mouse path are near-unique._

## Send Timing (two flush points)

1. **Existing `sendData()`** — fires after `init()` completes (unchanged). Sends
   whatever behavioral data accumulated by load time.
2. **NEW pre-unload flush** — `visibilitychange` (state `hidden`) and
   `pagehide` listeners call a `flushBehavioral()` that finalizes `dwellMs`,
   then POSTs via the same `/api/collect-advanced-data` endpoint with a
   `behavioralFlush: true` flag. Server `send_advanced_data_to_discord` merges
   the flush payload into the same `data.behavioral` before embed build (the
   function already reads `data` as a dict). `sendBeacon` is the transport of
   choice for `pagehide` (survives navigation); falls back to `fetch` keepalive.

The flush is a separate POST, not a replacement — early visitors still get the
load-time report; long-dwell visitors get the enriched follow-up.

## Files

- **Edit (append-only):** `static/js/advanced-collection.js`
  - Replace the empty-array body of `collectBehavioralData()` with real
    listeners + caps.
  - Add `flushBehavioral()` + `pagehide`/`visibilitychange` registration.
  - Add `sendBeacon`/`fetch keepalive` path in `sendData()` (guarded).
- **Edit (append-only):** `surveillance_embeds.py`
  - Add `_build_behavioral_field(data)`.
  - Wire it into `create_combined_surveillance_embed` after
    `_build_advanced_fingerprinting` (new field, doesn't touch existing).
  - Extend `_build_risk_assessment` behavioral scoring (additive).
- **Do NOT edit:** `main.py` route logic (the merge-on-flush is inside
  `send_advanced_data_to_discord` which already treats `data` as a dict — no
  signature change needed, the flush just overwrites `data.behavioral`).
- **Do NOT edit:** `templates/result.html` (the script tag already loads
  `advanced-collection.js`).

## Tests (Python — no JS infra)

Add to `tests/test_surveillance_embeds.py`:
- Feed a populated `behavioral` dict (dwell, scroll, sampled mouse/clicks/
  keystrokes/touch, transitions) → assert "BEHAVIORAL BIOMETRICS" field
  present, dwell value rendered, "timing only" note present, no raw array dump.
- Feed `behavioral: {error: "..."}` → assert field absent (skipped).
- Feed keystroke data → assert NO key content appears anywhere in any field
  value (the no-content invariant, enforced by test).
- Risk assessment: behavioral with keystrokes → score higher than without.

## Constraints Recap

- **No key content. Ever.** Timing only. (Loud comment + test guard.)
- **Append-only** to both JS and embed files — no rewrite of existing vectors.
- **Bounded sampling** — all arrays capped (50/25/30/30/20); counts uncapped.
- **Two flush points** — load-time + pre-unload via sendBeacon.

## Deferred

- Keystroke-content capture (intentionally never — out of scope, unsafe).
- Cross-session behavioral re-identification linkage (Phase E+, needs server
  storage + the device_tracker fingerprint).
- ML-based "is human" scoring on the cadence vectors (Phase E+).
