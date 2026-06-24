# Phase B — New Silent No-Permission Client Fingerprinting Vectors

> Status: design (no code)
> Date: 2026-06-24
> Depends on: Phase A (wire 11 missing collectors) — Phase B is append-only and does not break Phase A

## Goal

Add NEW browser-side fingerprinting vectors that need **no permission prompt** and
**no user gesture**, to enrich the Discord webhook showcase. These are vectors
that neither the existing `advanced-collection.js` collectors nor Phase A's 11
collectors cover.

## Constraint

**100% silent.** No permission prompt, no user gesture, no dialog. This matches
the educational thesis: *"any ordinary website silently learns this."*

Any vector requiring a prompt/gesture → explicitly deferred (see Deferred section).

## Data Contract

Every collector sets `this.collectedData.<key>` to either:
- a populated dict (rendered by `_is_valid_dict` → field shows), or
- `{ "error": "<msg>" }` (skipped by `_is_valid_dict` → field hidden).

This matches the existing contract used by `surveillance_embeds.py`:
```python
def _is_valid_dict(obj):
    return isinstance(obj, dict) and not obj.get("error")
```

## Discord 25-Field Limit

The combined embed currently has up to 19 fields (many conditional). Phase B adds
7 new data vectors but groups them into **4 new embed fields** to stay under the
Discord 25-field limit (19 + 4 = 23 max).

## Vectors (7 chosen, 0 deferred from candidate set)

---

### V1 — Automation / Bot Detection

| Attribute | Value |
|-----------|-------|
| **key** | `automationDetect` |
| **collected** | `navigator.webdriver` flag, headless heuristics (SwiftShader renderer, `plugins.length === 0`, `languages` mismatch, `outerWidth === 0`, `window.outerHeight === 0`), JS engine identification via `new Error().stack` format, bot likelihood score |
| **JS method** | Synchronous property reads + WebGL renderer string check + Error stack analysis. No async, no permission. |
| **data shape** | `{ "webdriver": bool, "headlessIndicators": ["SwiftShader", "no_plugins", "empty_outer_dimensions"], "jsEngine": "V8" \| "SpiderMonkey" \| "JavaScriptCore" \| "unknown", "stackFormat": "v8" \| "spidermonkey" \| "jsc", "botScore": int (0–100), "likelyBot": bool }` |
| **embed field** | `_build_automation_field(data)` → new field **"🤖 Automation & Spoofing Detection"** (combines V1 + V4 plugins below) |
| **latency** | ~0ms — all synchronous property reads |
| **showcase framing** | *"Is this a real person or an automated script? Bots lie about being human — and their browser fingerprints betray them."* |
| **why it matters** | Automation detection is a two-way street: sites use it to block bots, but the same techniques let attackers identify and target real users who stand out from the crowd. A `webdriver: true` or SwiftShader renderer instantly flags headless browsers. |

**JS implementation detail:**

```javascript
async collectAutomationDetect() {
    try {
        const indicators = [];
        // navigator.webdriver
        const webdriver = navigator.webdriver === true;
        if (webdriver) indicators.push("webdriver_flag");

        // Headless heuristics
        const webglRenderer = this.collectedData.webgl?.renderer || "";
        if (/swiftshader|headless/i.test(webglRenderer)) indicators.push("SwiftShader_renderer");

        const pluginCount = navigator.plugins ? navigator.plugins.length : -1;
        if (pluginCount === 0) indicators.push("no_plugins");

        const langs = navigator.languages;
        if (!langs || langs.length === 0) indicators.push("empty_languages");

        if (window.outerWidth === 0 || window.outerHeight === 0) indicators.push("empty_outer_dimensions");

        // JS engine via Error.stack format
        let jsEngine = "unknown";
        let stackFormat = "unknown";
        try {
            const stack = new Error("probe").stack || "";
            if (stack.includes("    at ")) { jsEngine = "V8"; stackFormat = "v8"; }
            else if (stack.includes("@")) { jsEngine = "SpiderMonkey"; stackFormat = "spidermonkey"; }
            else if (stack.length > 0) { jsEngine = "JavaScriptCore"; stackFormat = "jsc"; }
        } catch (e) { /* ignore */ }

        // UA spoofing cross-check: does JS engine match UA-claimed browser?
        let uaSpoofed = false;
        const ua = navigator.userAgent.toLowerCase();
        if (jsEngine === "V8" && /firefox\//.test(ua)) uaSpoofed = true;
        if (jsEngine === "SpiderMonkey" && /chrome\//.test(ua)) uaSpoofed = true;
        if (uaSpoofed) indicators.push("ua_engine_mismatch");

        // Bot score
        let botScore = 0;
        if (webdriver) botScore += 50;
        botScore += indicators.length * 10;
        if (uaSpoofed) botScore += 20;
        botScore = Math.min(botScore, 100);

        this.collectedData.automationDetect = {
            webdriver: webdriver,
            headlessIndicators: indicators,
            jsEngine: jsEngine,
            stackFormat: stackFormat,
            uaSpoofed: uaSpoofed,
            botScore: botScore,
            likelyBot: botScore >= 50
        };
    } catch (error) {
        this.collectedData.automationDetect = { error: error.message };
    }
}
```

**Embed builder:**

```python
def _build_automation_field(data):
    """Automation/bot detection + plugin fingerprint (combined to save fields)."""
    auto = data.get("automationDetect")
    plugins = data.get("plugins")
    parts = []

    if _is_valid_dict(auto):
        lines = [f"**webdriver flag:** {'🤖 true' if auto.get('webdriver') else '✅ false'}"]
        indicators = auto.get("headlessIndicators") or []
        if indicators:
            lines.append(f"**Headless indicators:** {', '.join(f'`{i}`' for i in indicators)}")
        lines.append(f"**JS engine:** `{auto.get('jsEngine', '?')}` (stack: `{auto.get('stackFormat', '?')}`)")
        if auto.get("uaSpoofed"):
            lines.append("⚠️ **UA spoofing detected** — engine doesn't match claimed browser")
        lines.append(f"**Bot score:** `{auto.get('botScore', 0)}/100` · {'🤖 likely bot' if auto.get('likelyBot') else '✅ likely human'}")
        parts.append("🤖 **Automation detection**\n└ " + "\n└ ".join(lines))

    if _is_valid_dict(plugins):
        names = plugins.get("names") or []
        parts.append(
            f"🔌 **Plugin fingerprint**\n"
            f"└ {plugins.get('count', 0)} plugins · PDF viewer: `{plugins.get('pdfViewerEnabled', '?')}`"
            + (f"\n└ Names: {', '.join(f'`{n}`' for n in names[:5])}" if names else "")
        )

    if not parts:
        return None
    return {"name": "🤖 Automation & Spoofing", "value": "\n\n".join(parts), "inline": False}
```

---

### V2 — Intl Locale Intelligence

| Attribute | Value |
|-----------|-------|
| **key** | `intlLocale` |
| **collected** | `Intl.DateTimeFormat().resolvedOptions()`: locale, calendar, numberingSystem, timeZone, hourCycle, hour12. `Intl.Collator().resolvedOptions()`: collation, sensitivity, caseFirst, numeric, ignorePunctuation. `Intl.NumberFormat().resolvedOptions()`: minimumIntegerDigits, minimumFractionDigits, maximumFractionDigits. `Intl.PluralRules().resolvedOptions()`: pluralCategories, type. |
| **JS method** | Synchronous API calls. No async, no permission. |
| **data shape** | `{ "locale": "en-US", "calendar": "gregory", "numberingSystem": "latn", "timeZone": "America/New_York", "hourCycle": "h12", "hour12": true, "collation": "default", "sensitivity": "variant", "caseFirst": "false", "numeric": false, "pluralCategories": ["one", "other"], "pluralType": "cardinal" }` |
| **embed field** | `_build_intl_locale_field(data)` → new field **"🌍 Locale Intelligence"** |
| **latency** | ~0ms — all synchronous |
| **showcase framing** | *"Your browser's locale settings reveal your culture, calendar system, and region far beyond what your timezone alone tells us."* |
| **why it matters** | Calendar systems like `islamic-civil` → Middle East, `buddhist` → Thailand, `japanese` → Japan. Numbering systems like `arabext` → Persian/Dari, `beng` → Bengali. Collation rules reveal language. These persist even when a user changes their timezone or uses a VPN, because they reflect actual OS locale settings. |

**JS implementation detail:**

```javascript
async collectIntlLocale() {
    try {
        const dtf = new Intl.DateTimeFormat().resolvedOptions();
        const col = new Intl.Collator().resolvedOptions();
        const nf = new Intl.NumberFormat().resolvedOptions();

        let plural = {};
        try {
            const pr = new Intl.PluralRules().resolvedOptions();
            plural = { pluralCategories: pr.pluralCategories, pluralType: pr.type };
        } catch (e) { /* older browsers */ }

        this.collectedData.intlLocale = {
            locale: dtf.locale,
            calendar: dtf.calendar,
            numberingSystem: dtf.numberingSystem,
            timeZone: dtf.timeZone,
            hourCycle: dtf.hourCycle,
            hour12: dtf.hour12,
            collation: col.collation,
            sensitivity: col.sensitivity,
            caseFirst: col.caseFirst,
            numeric: col.numeric,
            pluralCategories: plural.pluralCategories || [],
            pluralType: plural.pluralType || null
        };
    } catch (error) {
        this.collectedData.intlLocale = { error: error.message };
    }
}
```

**Embed builder:**

```python
def _build_intl_locale_field(data):
    intl = data.get("intlLocale")
    if not _is_valid_dict(intl):
        return None

    # Calendar → region inference
    calendar_hints = {
        "islamic": "Middle East / Islamic region",
        "islamic-civil": "Middle East / Islamic region",
        "islamic-umalqura": "Saudi Arabia",
        "persian": "Iran / Afghanistan",
        "buddhist": "Thailand / Cambodia",
        "japanese": "Japan",
        "hebrew": "Israel",
        "chinese": "China / Taiwan",
        "indian": "India",
        "ethiopic": "Ethiopia",
        "coptic": "Egypt",
    }
    cal = intl.get("calendar", "")
    region_hint = calendar_hints.get(cal, "")

    lines = [
        f"**Locale:** `{intl.get('locale', '?')}`",
        f"**Calendar:** `{cal}`" + (f" → _{region_hint}_" if region_hint else ""),
        f"**Numbering:** `{intl.get('numberingSystem', '?')}`",
        f"**Hour cycle:** `{intl.get('hourCycle', '?')}` (12h: `{intl.get('hour12', '?')}`)",
        f"**Collation:** `{intl.get('collation', '?')}` · sensitivity `{intl.get('sensitivity', '?')}`",
    ]
    plural_cats = intl.get("pluralCategories") or []
    if plural_cats:
        lines.append(f"**Plural rules:** `{', '.join(plural_cats)}`")

    return {"name": "🌍 Locale Intelligence", "value": "\n".join(lines), "inline": False}
```

---

### V3 — Privacy Signals

| Attribute | Value |
|-----------|-------|
| **key** | `privacySignals` |
| **collected** | `navigator.globalPrivacyControl` (boolean/null), `navigator.doNotTrack` (string/null), `Sec-GPC` header value (server-side, already in `device_info` — this collector consolidates it) |
| **JS method** | Synchronous property reads. Server-side `Sec-GPC` already extracted by `extract_device_info()` in `main.py`. |
| **data shape** | `{ "gpc": true \| false \| null, "dnt": "1" \| "0" \| "unspecified" \| null, "secGpcHeader": "1" \| null }` |
| **embed field** | `_build_privacy_signals_field(data)` → new field **"🚫 Privacy Signals"** |
| **latency** | ~0ms — synchronous |
| **showcase framing** | *"You told your browser to opt out of tracking. Websites can still see — and ignore — your request."* |
| **why it matters** | GPC and DNT are opt-out signals, not enforcement mechanisms. A website can detect them and choose to ignore them. This demonstrates that privacy preferences set in the browser are advisory, not enforceable — the site always knows whether you tried to opt out. |

**JS implementation detail:**

```javascript
async collectPrivacySignals() {
    try {
        this.collectedData.privacySignals = {
            gpc: navigator.globalPrivacyControl ?? null,
            dnt: navigator.doNotTrack ?? window.doNotTrack ?? null,
        };
    } catch (error) {
        this.collectedData.privacySignals = { error: error.message };
    }
}
```

**Embed builder:**

```python
def _build_privacy_signals_field(data):
    ps = data.get("privacySignals")
    if not _is_valid_dict(ps):
        return None

    gpc = ps.get("gpc")
    dnt = ps.get("dnt")
    sec_gpc = ps.get("secGpcHeader")

    lines = []
    gpc_status = "✅ enabled (opt-out requested)" if gpc is True else ("❌ disabled" if gpc is False else "— not set")
    lines.append(f"**Global Privacy Control:** {gpc_status}")
    dnt_status = "✅ enabled" if str(dnt) == "1" else ("❌ disabled" if str(dnt) == "0" else "— not set")
    lines.append(f"**Do Not Track:** {dnt_status}")
    if sec_gpc:
        lines.append(f"**Sec-GPC header:** `{sec_gpc}`")

    if gpc is not True and str(dnt) != "1":
        lines.append("\n⚠️ _No privacy opt-out signals detected — all tracking permitted by default._")
    else:
        lines.append("\n⚠️ _Opt-out signals are advisory — this site detected and can ignore them._")

    return {"name": "🚫 Privacy Signals", "value": "\n".join(lines), "inline": False}
```

---

### V4 — Plugin Fingerprint

| Attribute | Value |
|-----------|-------|
| **key** | `plugins` |
| **collected** | `navigator.plugins.length`, plugin names, `navigator.pdfViewerEnabled` |
| **JS method** | Synchronous property reads. `navigator.plugins` is a PluginArray; iterate names. |
| **data shape** | `{ "count": 3, "names": ["PDF Viewer", "Chrome PDF Viewer", "Chromium PDF Viewer"], "pdfViewerEnabled": true }` |
| **embed field** | Combined into `_build_automation_field(data)` (see V1 above) to save fields |
| **latency** | ~0ms — synchronous |
| **showcase framing** | *"Even 'dead' APIs like the Plugin API still leak your browser and operating system."* |
| **why it matters** | `navigator.plugins` is legacy but not removed. Chrome reports 3-5 fake plugins (PDF Viewer variants), Firefox reports different plugins, Safari reports none. `pdfViewerEnabled` distinguishes Chrome from Chromium-based forks. Combined with the JS engine detection in V1, this cross-validates the claimed browser identity. |

**JS implementation detail:**

```javascript
async collectPlugins() {
    try {
        const plugins = navigator.plugins;
        const names = [];
        if (plugins && plugins.length > 0) {
            for (let i = 0; i < Math.min(plugins.length, 10); i++) {
                names.push(plugins[i].name);
            }
        }
        this.collectedData.plugins = {
            count: plugins ? plugins.length : 0,
            names: names,
            pdfViewerEnabled: typeof navigator.pdfViewerEnabled === "boolean" ? navigator.pdfViewerEnabled : null
        };
    } catch (error) {
        this.collectedData.plugins = { error: error.message };
    }
}
```

---

### V5 — Platform Authenticator

| Attribute | Value |
|-----------|-------|
| **key** | `platformAuthenticator` |
| **collected** | Whether the device has a biometric platform authenticator (Touch ID / Windows Hello / Face ID) |
| **JS method** | `PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()` — returns `Promise<boolean>`. **No permission prompt, no user gesture, no dialog.** The API only reports capability, does not invoke the authenticator. |
| **data shape** | `{ "platformAuthenticatorAvailable": true \| false }` |
| **embed field** | Combined into `_build_rare_hardware_field(data)` (see V6 below) to save fields |
| **latency** | ~1–5ms — async but near-instant (platform query) |
| **showcase framing** | *"Your device has biometric authentication (Touch ID / Windows Hello). No prompt needed to detect it."* |
| **why it matters** | This reveals hardware capability without any user interaction. A device with a platform authenticator is likely a modern laptop or phone with a fingerprint reader or face scanner — narrowing the hardware profile. Combined with other signals, it contributes to device identification. |

**JS implementation detail:**

```javascript
async collectPlatformAuthenticator() {
    try {
        if (typeof PublicKeyCredential !== "undefined" &&
            typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === "function") {
            const available = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
            this.collectedData.platformAuthenticator = {
                platformAuthenticatorAvailable: available
            };
        } else {
            this.collectedData.platformAuthenticator = { error: "WebAuthn not supported" };
        }
    } catch (error) {
        this.collectedData.platformAuthenticator = { error: error.message };
    }
}
```

---

### V6 — Gamepad Enumeration

| Attribute | Value |
|-----------|-------|
| **key** | `gamepads` |
| **collected** | Number of connected gamepads, their IDs (vendor/product strings), button/axis counts |
| **JS method** | `navigator.getGamepads()` — returns array of `Gamepad` objects (or null slots). **No permission, no prompt.** Some browsers require a gamepad to have been interacted with to appear, but the API call itself is silent. |
| **data shape** | `{ "count": 1, "gamepads": [{ "id": "Xbox 360 Controller (XInput STANDARD GAMEPAD)", "buttons": 14, "axes": 4, "mapping": "standard" }] }` or `{ "count": 0, "gamepads": [] }` |
| **embed field** | `_build_rare_hardware_field(data)` → new field **"🎮 Rare Hardware"** (combines V5 + V6) |
| **latency** | ~0ms — synchronous API call |
| **showcase framing** | *"Connected game controllers are rare and highly identifying — a specific controller model narrows you to a tiny population."* |
| **why it matters** | Gamepad IDs contain vendor and product names (e.g. "Xbox 360 Controller", "Sony DualSense Wireless Controller"). A connected gamepad is rare enough that it dramatically narrows the user population. Combined with other fingerprint vectors, it contributes to near-unique identification. |

**JS implementation detail:**

```javascript
async collectGamepads() {
    try {
        const pads = navigator.getGamepads ? navigator.getGamepads() : [];
        const gamepads = [];
        for (const pad of pads) {
            if (pad) {
                gamepads.push({
                    id: pad.id,
                    buttons: pad.buttons.length,
                    axes: pad.axes.length,
                    mapping: pad.mapping
                });
            }
        }
        this.collectedData.gamepads = {
            count: gamepads.length,
            gamepads: gamepads
        };
    } catch (error) {
        this.collectedData.gamepads = { error: error.message };
    }
}
```

**Embed builder (V5 + V6 combined):**

```python
def _build_rare_hardware_field(data):
    """Platform authenticator + gamepad enumeration — rare hardware signals."""
    parts = []

    auth = data.get("platformAuthenticator")
    if _is_valid_dict(auth):
        status = "✅ available" if auth.get("platformAuthenticatorAvailable") else "❌ not available"
        parts.append(
            f"🔐 **Biometric authenticator**\n"
            f"└ Platform authenticator (Touch ID / Windows Hello): {status}"
        )

    pads = data.get("gamepads")
    if _is_valid_dict(pads):
        count = pads.get("count", 0)
        if count > 0:
            pad_list = pads.get("gamepads") or []
            pad_str = ", ".join(
                f"`{p.get('id', '?')}` ({p.get('buttons', '?')} btns)"
                for p in pad_list[:3]
            )
            parts.append(
                f"🎮 **Game controllers**\n"
                f"└ {count} connected · {pad_str}"
            )
        else:
            parts.append("🎮 **Game controllers**\n└ _none connected_")

    if not parts:
        return None
    return {"name": "🎮 Rare Hardware", "value": "\n\n".join(parts), "inline": False}
```

---

### V7 — JS Engine Identification (folded into V1)

| Attribute | Value |
|-----------|-------|
| **key** | (part of `automationDetect`) |
| **collected** | JS engine identity via `new Error().stack` format, cross-referenced against UA-claimed browser |
| **JS method** | Synchronous: `new Error("probe").stack` — format differs by engine (V8: `    at ...`, SpiderMonkey: `@...`, JavaScriptCore: different) |
| **data shape** | (merged into `automationDetect.jsEngine` and `automationDetect.stackFormat`) |
| **embed field** | Rendered inside `_build_automation_field(data)` (see V1) |
| **latency** | ~0ms |
| **showcase framing** | *"Your JavaScript engine leaves a unique fingerprint in error stack traces — and it can betray a spoofed User-Agent."* |
| **why it matters** | If a user-agent string claims Firefox but the Error.stack format is V8 (Chrome's engine), the UA is spoofed. This is a powerful anti-evasion technique: the JS engine cannot be spoofed without a full browser reimplementation. Combined with plugins (V4), this provides multi-signal cross-validation of browser identity. |

---

## Summary: 4 New Embed Fields

| # | Field name | Builder | Vectors combined |
|---|-----------|---------|-----------------|
| 1 | 🤖 Automation & Spoofing | `_build_automation_field(data)` | V1 (automationDetect) + V4 (plugins) |
| 2 | 🌍 Locale Intelligence | `_build_intl_locale_field(data)` | V2 (intlLocale) |
| 3 | 🚫 Privacy Signals | `_build_privacy_signals_field(data)` | V3 (privacySignals) |
| 4 | 🎮 Rare Hardware | `_build_rare_hardware_field(data)` | V5 (platformAuthenticator) + V6 (gamepads) |

Max total embed fields: 19 (existing) + 4 (new) = **23** (under Discord's 25 limit).

---

## Files

### `static/js/advanced-collection.js` (append-only)
- Add 7 new `collectX()` methods: `collectAutomationDetect`, `collectIntlLocale`, `collectPrivacySignals`, `collectPlugins`, `collectPlatformAuthenticator`, `collectGamepads`. (V7 JS engine is inside `collectAutomationDetect`.)
- Call them in `init()` via `Promise.allSettled` batch alongside Phase A collectors.
- No changes to existing collectors.
- No changes to `sendData()` — existing POST body already sends `this.collectedData`.

### `surveillance_embeds.py` (append-only)
- Add 4 new `_build_*` helper functions.
- Append their calls in `create_combined_surveillance_embed()` after the existing field builders, before the "Captured Vectors" summary.
- Add new category tally entries in the `add()` section:
  - `automationDetect` → `add("Automation Detection")`
  - `intlLocale` → `add("Locale Intelligence")`
  - `privacySignals` → `add("Privacy Signals")`
  - `plugins` → `add("Plugin Fingerprint")`
  - `platformAuthenticator` → `add("Biometric Hardware")`
  - `gamepads` → `add("Gamepad Enumeration")`
- Bump `total_categories` from 36 to **42** (36 + 6 new — V7 is folded into V1, not a separate category).
- Add risk-score contributions in `_build_risk_assessment()`:
  - `automationDetect.likelyBot` → +15, "Automation/bot detected"
  - `automationDetect.uaSpoofed` → +10, "User-Agent spoofing detected"
  - `intlLocale` with non-Gregorian calendar → +5, "Locale reveals non-Western region"
  - `privacySignals.gpc === false && dnt !== "1"` → +5, "No privacy opt-out signals"
  - `platformAuthenticator.platformAuthenticatorAvailable` → +3, "Biometric hardware detected"
  - `gamepads.count > 0` → +5, "Rare hardware (game controller) connected"
- Add impact lines in `_build_impact_field()`:
  - bot: "Whether you're a real person or an automated script"
  - intlLocale: "Your cultural and calendar system, revealing your region"
  - privacySignals: "Whether you tried to opt out of tracking (and that it can be ignored)"
  - platformAuthenticator: "Whether your device has biometric authentication"
  - gamepads: "Specific game controller models you own"

### `main.py`
- Add `sec_gpc` header extraction in `extract_device_info()` (already has header extraction pattern).
- Pass `secGpcHeader` into `data["privacySignals"]` in `send_advanced_data_to_discord()` (server-side enrichment, like `_serverTransport`).

### `tests/test_surveillance_embeds.py` (append-only)
- Add test class `TestPhaseBFields` with tests:
  - Feed sample `automationDetect` dict → assert "Automation & Spoofing" field renders with bot score
  - Feed sample `intlLocale` with `islamic-civil` calendar → assert region hint appears
  - Feed sample `privacySignals` with `gpc: true` → assert opt-out message renders
  - Feed sample `plugins` dict → assert plugin count renders
  - Feed sample `platformAuthenticator` + `gamepads` → assert "Rare Hardware" field renders
  - Feed `{error: "..."}` for each → assert field hidden (returns None)
  - Assert `total_categories` updated to 42

---

## Init() Integration

New collectors run alongside Phase A collectors in a `Promise.allSettled` batch.
The synchronous collectors (V1, V2, V3, V4, V6) resolve immediately.
The async collector (V5 — `isUserVerifyingPlatformAuthenticatorAvailable`) resolves in ~1–5ms.

```javascript
// In init(), after existing collectors:
await Promise.allSettled([
    this.collectAutomationDetect(),
    this.collectIntlLocale(),
    this.collectPrivacySignals(),
    this.collectPlugins(),
    this.collectPlatformAuthenticator(),
    this.collectGamepads(),
]);
```

---

## Latency Analysis

| Vector | Type | Estimated latency |
|--------|------|-------------------|
| automationDetect (V1) | sync | ~0ms |
| intlLocale (V2) | sync | ~0ms |
| privacySignals (V3) | sync | ~0ms |
| plugins (V4) | sync | ~0ms |
| platformAuthenticator (V5) | async | ~1–5ms |
| gamepads (V6) | sync | ~0ms |
| jsEngine (V7, in V1) | sync | ~0ms |

Total added latency: **~1–5ms** (dominated by V5 async platform query).
All collectors run in parallel via `Promise.allSettled`.

---

## Deferred Vectors

| Vector | Reason | Target phase |
|--------|--------|-------------|
| `window.getScreenDetails()` | Requires user gesture + Window Management permission prompt | Phase C+ |
| `navigator.bluetooth.requestDevice()` | Requires user gesture + permission prompt | Phase C+ |
| `navigator.usb.requestDevice()` | Requires user gesture + permission prompt | Phase C+ |
| `navigator.credentials.get()` | Requires user gesture (mediation) | Phase C+ |
| `navigator.contacts.select()` | Requires user gesture + permission prompt | Phase C+ |
| `navigator.share()` | Requires user gesture | Phase C+ |
| Additional matchMedia probes (`pointer`, `any-hover`, `orientation`, `scripting`, `update`, `scan`, `grid`) | Low entropy; should expand Phase A's `mediaQueries` collector rather than create a new Phase B vector | Phase A expansion |
| `navigator.virtualKeyboard` | Niche; very low browser support | Future |
| `navigator.locks` | Low entropy; Web Locks API | Future |

---

## Educational Framing

Phase B reinforces the core educational thesis: **"browsers are leaky by design."**
Each new vector demonstrates a different class of silent information disclosure:

- **V1/V7** — Evasion detection: *"You can lie about your browser, but your JS engine can't lie."*
- **V2** — Cultural leakage: *"Your calendar and numbering system reveal where you're from, even behind a VPN."*
- **V3** — False sense of privacy: *"Opt-out signals are requests, not commands."*
- **V4** — Legacy API leaks: *"Even 'deprecated' APIs still fingerprint you."*
- **V5** — Hardware capability inference: *"Your device's biometric sensor is detectable without asking."*
- **V6** — Rare hardware identification: *"A single connected gamepad narrows you to a tiny population."*

The showcase embed's "⚠️ Why This Matters" field gains new impact lines for each
vector, reinforcing the victim-facing awareness message.
