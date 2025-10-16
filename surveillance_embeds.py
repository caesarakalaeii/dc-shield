"""
Educational Discord Embed Functions for DC-Shield
Provides cybersecurity awareness demonstrations with educational context and learning objectives
Educational tool for demonstrating web vulnerabilities and privacy implications
"""


# ANSI Color Codes for Discord
class AnsiColor:
    """ANSI color formatting for Discord code blocks"""
    # Format codes
    RESET = "\u001b[0m"
    BOLD = "\u001b[1m"
    UNDERLINE = "\u001b[4m"

    # Text colors
    GRAY = "\u001b[30m"
    RED = "\u001b[31m"
    GREEN = "\u001b[32m"
    YELLOW = "\u001b[33m"
    BLUE = "\u001b[34m"
    PINK = "\u001b[35m"
    CYAN = "\u001b[36m"
    WHITE = "\u001b[37m"

    # Background colors
    BG_DARK_BLUE = "\u001b[40m"
    BG_ORANGE = "\u001b[41m"
    BG_MARBLE_BLUE = "\u001b[42m"
    BG_TURQUOISE = "\u001b[43m"
    BG_GRAY = "\u001b[44m"
    BG_INDIGO = "\u001b[45m"
    BG_LIGHT_GRAY = "\u001b[46m"
    BG_WHITE = "\u001b[47m"


def ansi_format(text, color=None, bold=False, underline=False, bg_color=None):
    """
    Format text with ANSI color codes for Discord

    Args:
        text: The text to format
        color: Text color code (e.g., AnsiColor.RED)
        bold: Whether to make text bold
        underline: Whether to underline text
        bg_color: Background color code

    Returns:
        Formatted text with ANSI codes
    """
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
        formatted = "".join(codes) + text + AnsiColor.RESET
        return formatted
    return text


def create_progress_bar(percentage, length=10):
    """Create a visual progress bar using Discord-compatible characters with color coding"""
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
    """Format bytes into human readable format"""
    if not bytes_value or bytes_value == 0:
        return "0 B"

    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if bytes_value < 1024.0:
            return f"{bytes_value:.1f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.1f} PB"


def get_threat_indicator(score):
    """Get threat level indicator with hacker theme color coding for educational demonstration"""
    if score >= 80:
        colored_text = ansi_format("⚠️ CRITICAL_THREAT", color=AnsiColor.RED, bold=True)
        return colored_text, 0xFF0000  # Red
    elif score >= 60:
        colored_text = ansi_format("⚡ HIGH_RISK", color=AnsiColor.YELLOW, bold=True)
        return colored_text, 0xFF4500  # Orange-Red
    elif score >= 40:
        colored_text = ansi_format("⚙️ MODERATE_ALERT", color=AnsiColor.CYAN, bold=True)
        return colored_text, 0xFFFF00  # Yellow
    elif score >= 20:
        colored_text = ansi_format("✓ LOW_EXPOSURE", color=AnsiColor.GREEN, bold=True)
        return colored_text, 0x00FF00  # Matrix Green
    else:
        colored_text = ansi_format("○ MINIMAL_TRACE", color=AnsiColor.GREEN)
        return colored_text, 0x00AA00  # Dark Green


def get_security_lesson(vulnerability_type):
    """Get educational content about specific vulnerabilities"""
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


def create_combined_surveillance_embed(data, recognition_info=None):
    """
    Create an educational embed demonstrating data collection capabilities for cybersecurity awareness

    Args:
        data: Collected browser fingerprinting data
        recognition_info: Optional device recognition information from device_tracker
    """
    from datetime import datetime

    # Calculate comprehensive metrics
    categories_captured = 0
    total_categories = 15  # Increased for more categories
    critical_data_found = False

    # Enhanced category tracking
    captured_categories = []

    def is_valid_dict_with_no_error(obj):
        return isinstance(obj, dict) and not obj.get("error")

    if data.get("screen"):
        categories_captured += 1
        captured_categories.append("Display")
    if is_valid_dict_with_no_error(data.get("geolocation")):
        categories_captured += 1
        captured_categories.append("GPS Location")
        critical_data_found = True
    if data.get("camera", {}).get("captured"):
        categories_captured += 1
        captured_categories.append("Camera Access")
        critical_data_found = True
    if is_valid_dict_with_no_error(data.get("battery")):
        categories_captured += 1
        captured_categories.append("Battery")
    if isinstance(data.get("mediaDevices"), list):
        categories_captured += 1
        captured_categories.append("Media Devices")
    elif (
        data.get("mediaDevices")
        and not isinstance(data.get("mediaDevices"), list)
        and not data["mediaDevices"].get("error")
    ):
        categories_captured += 1
        captured_categories.append("Media Devices")
    if is_valid_dict_with_no_error(data.get("network")):
        categories_captured += 1
        captured_categories.append("Network")
    if is_valid_dict_with_no_error(data.get("storage")):
        categories_captured += 1
        captured_categories.append("Storage")
    if is_valid_dict_with_no_error(data.get("clipboard")):
        categories_captured += 1
        captured_categories.append("Clipboard")
        critical_data_found = True
    if data.get("canvas"):
        categories_captured += 1
        captured_categories.append("Canvas Fingerprint")
    if is_valid_dict_with_no_error(data.get("webgl")):
        categories_captured += 1
        captured_categories.append("WebGL Fingerprint")
    if data.get("memory"):
        categories_captured += 1
        captured_categories.append("Memory Profile")
    if data.get("timezone"):
        categories_captured += 1
        captured_categories.append("Timezone")
    if data.get("viewport"):
        categories_captured += 1
        captured_categories.append("Viewport")
    if data.get("browser"):
        categories_captured += 1
        captured_categories.append("Browser Profile")
    if data.get("localStorage"):
        categories_captured += 1
        captured_categories.append("Local Storage")

    # NEW: Check for additional advanced data points
    total_categories = 22  # Increased for new categories

    if is_valid_dict_with_no_error(data.get("audioFingerprint")):
        categories_captured += 1
        captured_categories.append("Audio Fingerprint")
        critical_data_found = True
    if data.get("fonts") and not data.get("fonts", {}).get("error"):
        categories_captured += 1
        captured_categories.append("Font Detection")
    if data.get("webrtc") and data.get("webrtc", {}).get("leakDetected"):
        categories_captured += 1
        captured_categories.append("WebRTC Leak")
        critical_data_found = True
    if data.get("browserFeatures"):
        categories_captured += 1
        captured_categories.append("Browser Features")
    if data.get("behavioral"):
        categories_captured += 1
        captured_categories.append("Behavioral Tracking")
    if data.get("sensors") and len(data.get("sensors", {})) > 0:
        categories_captured += 1
        captured_categories.append("Hardware Sensors")
    if data.get("cpuBenchmark"):
        categories_captured += 1
        captured_categories.append("CPU Benchmark")

    success_rate = int((categories_captured / total_categories) * 100)
    threat_level, embed_color = get_threat_indicator(success_rate)

    # Build colored description
    desc_lines = []
    desc_lines.append(ansi_format(">> BREACH_ANALYSIS_INITIATED", color=AnsiColor.CYAN, bold=True))
    desc_lines.append(ansi_format(f">> THREAT_LEVEL: ", color=AnsiColor.WHITE) + threat_level)
    desc_lines.append(
        ansi_format(">> DATA_EXPOSURE: ", color=AnsiColor.WHITE) +
        ansi_format(f"{categories_captured}/{total_categories}", color=AnsiColor.YELLOW, bold=True) +
        ansi_format(" vectors compromised", color=AnsiColor.WHITE)
    )
    if critical_data_found:
        desc_lines.append(ansi_format(">> CRITICAL_VULNERABILITIES_DETECTED", color=AnsiColor.RED, bold=True))
    else:
        desc_lines.append(ansi_format(">> STANDARD_PROFILING_EXECUTED", color=AnsiColor.GREEN))
    desc_lines.append(ansi_format(">> Educational Demonstration | Authorized Training Environment", color=AnsiColor.GRAY))

    embed = {
        "title": ">> [[ SURVEILLANCE PROTOCOL ACTIVE ]]",
        "description": f"```ansi\n" + "\n".join(desc_lines) + "\n```",
        "color": embed_color,
        "timestamp": datetime.now().isoformat(),
        "fields": [],
        "footer": {
            "text": f"[[ DC-Shield Security Research ]] • {categories_captured} attack vectors analyzed • Educational Use Only",
            "icon_url": "https://cdn.discordapp.com/attachments/123456789/shield-icon.png",
        },
    }

    # Enhanced Overview with Progress Bar
    overview_lines = []
    overview_lines.append(ansi_format(">> DATA_HARVEST_EFFICIENCY", color=AnsiColor.CYAN, bold=True))
    overview_lines.append(create_progress_bar(success_rate) + "\n")
    overview_lines.append(
        ansi_format(">> VECTORS_COMPROMISED: ", color=AnsiColor.WHITE) +
        ansi_format(f"{categories_captured}/{total_categories}", color=AnsiColor.YELLOW, bold=True)
    )
    overview_lines.append(ansi_format(">> THREAT_ASSESSMENT: ", color=AnsiColor.WHITE) + threat_level)
    if critical_data_found:
        overview_lines.append(
            ansi_format(">> STATUS: ", color=AnsiColor.WHITE) +
            ansi_format("[!] CRITICAL_DATA_ACQUIRED", color=AnsiColor.RED, bold=True)
        )
    else:
        overview_lines.append(
            ansi_format(">> STATUS: ", color=AnsiColor.WHITE) +
            ansi_format("[+] STANDARD_PROFILING", color=AnsiColor.GREEN)
        )

    embed["fields"].append(
        {
            "name": ">> [[ BREACH OVERVIEW ]]",
            "value": f"```ansi\n" + "\n".join(overview_lines) + "\n```",
            "inline": False,
        }
    )

    # Device Recognition Section - Show if this is a returning device
    if recognition_info and recognition_info.get("is_returning"):
        recognition_lines = []

        if recognition_info.get("is_new_name"):
            # Same device, different name - ALERT!
            previous_names = recognition_info.get("previous_names", [])
            recognition_lines.append(ansi_format("[!] IDENTITY_SPOOFING_DETECTED", color=AnsiColor.RED, bold=True))
            recognition_lines.append("")
            recognition_lines.append(
                ansi_format(">> CURRENT_ALIAS: ", color=AnsiColor.WHITE) +
                ansi_format(recognition_info.get('current_name'), color=AnsiColor.YELLOW, bold=True)
            )
            recognition_lines.append("")
            recognition_lines.append(
                ansi_format(f">> PREVIOUS_IDENTITIES ({len(previous_names)}):", color=AnsiColor.CYAN)
            )
            for idx, name in enumerate(previous_names[-10:], 1):  # Show last 10 previous names
                recognition_lines.append(ansi_format(f"   {idx}. {name}", color=AnsiColor.GRAY))
        else:
            # Same device, same name - returning user
            recognition_lines.append(ansi_format("[+] DEVICE_FINGERPRINT_MATCHED", color=AnsiColor.GREEN, bold=True))
            recognition_lines.append("")
            recognition_lines.append(
                ansi_format(">> TARGET_ID: ", color=AnsiColor.WHITE) +
                ansi_format(recognition_info.get('current_name'), color=AnsiColor.CYAN, bold=True)
            )

        recognition_lines.append("")
        recognition_lines.append(ansi_format(">> SURVEILLANCE_LOG:", color=AnsiColor.CYAN))
        recognition_lines.append(
            ansi_format(f"   └─ TOTAL_VISITS: ", color=AnsiColor.WHITE) +
            ansi_format(str(recognition_info.get('visit_count', 0)), color=AnsiColor.YELLOW, bold=True)
        )
        recognition_lines.append(
            ansi_format(f"   └─ FIRST_CONTACT: ", color=AnsiColor.WHITE) +
            ansi_format(recognition_info.get('first_seen', 'Unknown')[:16], color=AnsiColor.GRAY)
        )
        recognition_lines.append(
            ansi_format(f"   └─ LAST_CONTACT: ", color=AnsiColor.WHITE) +
            ansi_format(recognition_info.get('last_seen', 'Unknown')[:16], color=AnsiColor.GRAY)
        )

        # Show previous IPs if available
        previous_ips = recognition_info.get("previous_ips", [])
        if len(previous_ips) > 1:
            recognition_lines.append("")
            recognition_lines.append(ansi_format(f">> IP_TRAIL ({len(previous_ips)}):", color=AnsiColor.CYAN))
            for ip in previous_ips[-5:]:  # Show last 5 IPs
                recognition_lines.append(ansi_format(f"   └─ {ip}", color=AnsiColor.YELLOW))

        # Show fingerprint hash
        recognition_lines.append("")
        recognition_lines.append(
            ansi_format(">> DEVICE_HASH: ", color=AnsiColor.WHITE) +
            ansi_format(recognition_info.get('fingerprint', 'Unknown')[:32] + "...", color=AnsiColor.PINK)
        )

        recognition_value = f"```ansi\n" + "\n".join(recognition_lines) + "\n```"
        recognition_value += f"\n*[Educational] Persistent device tracking via browser fingerprinting - identity changes are ineffective*"

        embed["fields"].append(
            {
                "name": (
                    "🚨 [[ IDENTITY SPOOFING DETECTED ]]"
                    if recognition_info.get("is_new_name")
                    else "♻️ [[ RETURNING DEVICE TRACKED ]]"
                ),
                "value": recognition_value,
                "inline": False,
            }
        )
    elif recognition_info and not recognition_info.get("is_returning"):
        # New device
        recognition_lines = []
        recognition_lines.append(ansi_format("[*] NEW_TARGET_ACQUIRED", color=AnsiColor.GREEN, bold=True))
        recognition_lines.append("")
        recognition_lines.append(
            ansi_format(">> TARGET_ALIAS: ", color=AnsiColor.WHITE) +
            ansi_format(recognition_info.get('current_name'), color=AnsiColor.CYAN, bold=True)
        )
        recognition_lines.append(
            ansi_format(">> FINGERPRINT_HASH: ", color=AnsiColor.WHITE) +
            ansi_format(recognition_info.get('fingerprint', 'Unknown')[:32] + "...", color=AnsiColor.PINK)
        )
        recognition_lines.append(ansi_format(">> STATUS: ", color=AnsiColor.WHITE) + ansi_format("Tracking initiated", color=AnsiColor.GREEN))

        recognition_value = f"```ansi\n" + "\n".join(recognition_lines) + "\n```"
        recognition_value += f"\n*[+] Device enrolled in persistent surveillance database*"

        embed["fields"].append(
            {
                "name": "✨ [[ NEW DEVICE FINGERPRINTED ]]",
                "value": recognition_value,
                "inline": False,
            }
        )

    # Critical Security Alerts with Enhanced Details
    critical_alerts = []

    if data.get("camera", {}).get("captured"):
        timestamp = data["camera"].get("timestamp", "Unknown")
        critical_alerts.append(
            f"📸 **CAMERA COMPROMISED**\n└ Image captured at {timestamp}\n└ Resolution: 640x480px"
        )

    if is_valid_dict_with_no_error(data.get("geolocation")) and data["geolocation"].get(
        "latitude"
    ):
        lat, lng = data["geolocation"].get("latitude"), data["geolocation"].get(
            "longitude"
        )
        accuracy = data["geolocation"].get("accuracy", "Unknown")
        critical_alerts.append(
            f"🌍 **PRECISE LOCATION ACQUIRED**\n└ Coordinates: `{lat:.6f}, {lng:.6f}`\n└ Accuracy: ±{accuracy}m"
        )

    # Critical alerts
    if is_valid_dict_with_no_error(data.get("clipboard")):
        clip_len = data["clipboard"].get("length", 0)
        preview = data["clipboard"].get("content", "")[:30]
        critical_alerts.append(
            f"📋 **CLIPBOARD INTERCEPTED**\n└ Content length: {clip_len} characters\n└ Preview: `{preview}...`"
        )

    if isinstance(data.get("mediaDevices"), list):
        devices = data["mediaDevices"]
        cam_count = sum(
            1 for d in devices if isinstance(d, dict) and d.get("kind") == "videoinput"
        )
        mic_count = sum(
            1 for d in devices if isinstance(d, dict) and d.get("kind") == "audioinput"
        )
        speaker_count = sum(
            1 for d in devices if isinstance(d, dict) and d.get("kind") == "audiooutput"
        )
        critical_alerts.append(
            f"🎥 **MEDIA DEVICES ENUMERATED**\n└ Cameras: {cam_count} | Microphones: {mic_count}\n└ Speakers: {speaker_count}"
        )
    elif (
        data.get("mediaDevices")
        and not isinstance(data.get("mediaDevices"), list)
        and not data["mediaDevices"].get("error")
    ):
        devices = data["mediaDevices"]
        cam_count = (
            sum(
                1
                for d in devices
                if isinstance(d, dict) and d.get("kind") == "videoinput"
            )
            if isinstance(devices, list)
            else 0
        )
        mic_count = (
            sum(
                1
                for d in devices
                if isinstance(d, dict) and d.get("kind") == "audioinput"
            )
            if isinstance(devices, list)
            else 0
        )
        speaker_count = (
            sum(
                1
                for d in devices
                if isinstance(d, dict) and d.get("kind") == "audiooutput"
            )
            if isinstance(devices, list)
            else 0
        )
        critical_alerts.append(
            f"🎥 **MEDIA DEVICES ENUMERATED**\n└ Cameras: {cam_count} | Microphones: {mic_count}\n└ Speakers: {speaker_count}"
        )

    # NEW: Add WebRTC leak detection
    if data.get("webrtc") and data.get("webrtc", {}).get("leakDetected"):
        local_ips = data["webrtc"].get("localIPs", [])
        if local_ips:
            critical_alerts.append(
                f"🔓 **WEBRTC IP LEAK DETECTED**\n└ Local IPs exposed: {', '.join(local_ips)}\n└ VPN bypass detected"
            )

    # NEW: Add audio fingerprint detection
    if is_valid_dict_with_no_error(data.get("audioFingerprint")):
        audio_hash = data["audioFingerprint"].get("hash", "unknown")[:16]
        critical_alerts.append(
            f"🔊 **AUDIO FINGERPRINT CAPTURED**\n└ Unique hardware ID: `{audio_hash}...`\n└ Can track across browsers"
        )

    if critical_alerts:
        embed["fields"].append(
            {
                "name": ">> [[ ⚠️ CRITICAL EXPLOITS SUCCESSFUL ]]",
                "value": "\n\n".join(critical_alerts),
                "inline": False,
            }
        )

    # Enhanced System Profile with Better Organization
    system_profile_left = []
    system_profile_right = []

    if data.get("screen"):
        screen = data["screen"]
        total_pixels = screen.get("width", 0) * screen.get("height", 0)
        system_profile_left.append(
            f"🖥️ **Display**\n└ {screen.get('width')}×{screen.get('height')} ({total_pixels:,} pixels)"
        )
        system_profile_left.append(
            f"└ Color depth: {screen.get('colorDepth', 'Unknown')} bits"
        )

    if data.get("browser", {}).get("hardwareConcurrency"):
        cores = data["browser"]["hardwareConcurrency"]
        system_profile_right.append(f"⚙️ **CPU**\n└ {cores} logical cores")

    if data.get("deviceMemory"):
        ram_gb = data["deviceMemory"]
        system_profile_right.append(f"💾 **RAM**\n└ {ram_gb} GB total")

    if data.get("memory"):
        memory = data["memory"]
        heap_used = format_bytes(memory.get("usedJSHeapSize", 0))
        heap_limit = format_bytes(memory.get("jsHeapSizeLimit", 0))
        system_profile_left.append(f"🧠 **JS Memory**\n└ {heap_used} / {heap_limit}")

    if data.get("timezone"):
        tz = data["timezone"]
        offset_hours = tz.get("offset", 0) / -60
        system_profile_right.append(f"🌐 **Location**\n└ {tz.get('name', 'Unknown')}")
        system_profile_right.append(f"└ UTC{offset_hours:+.1f}")

    if is_valid_dict_with_no_error(data.get("battery")):
        battery = data["battery"]
        level = int(battery.get("level", 0) * 100)
        status = "🔌 Charging" if battery.get("charging") else "🔋 Discharging"
        system_profile_left.append(f"🔋 **Battery**\n└ {level}% {status}")

    if is_valid_dict_with_no_error(data.get("network")):
        network = data["network"]
        speed_info = f"{network.get('downlink', 'Unknown')} Mbps"
        latency_info = f"{network.get('rtt', 'Unknown')}ms RTT"
        system_profile_right.append(
            f"📡 **Network**\n└ {network.get('effectiveType', 'Unknown')} ({speed_info})"
        )
        system_profile_right.append(f"└ Latency: {latency_info}")

    if system_profile_left:
        embed["fields"].append(
            {
                "name": ">> [[ HARDWARE_PROFILE ]]",
                "value": "\n\n".join(system_profile_left),
                "inline": True,
            }
        )

    if system_profile_right:
        embed["fields"].append(
            {
                "name": ">> [[ NETWORK_INTEL ]]",
                "value": "\n\n".join(system_profile_right),
                "inline": True,
            }
        )

    # NEW: Add Advanced Fingerprinting Section
    advanced_fingerprinting = []

    if data.get("fonts") and not data.get("fonts", {}).get("error"):
        font_count = data["fonts"].get("count", 0)
        installed_fonts = data["fonts"].get("installed", [])[:5]
        advanced_fingerprinting.append(
            f"🔤 **Font Fingerprinting**\n└ {font_count} unique fonts detected\n└ Sample: {', '.join(installed_fonts)}"
        )

    if data.get("cpuBenchmark"):
        cpu_score = data["cpuBenchmark"].get("score", 0)
        duration = data["cpuBenchmark"].get("duration", 0)
        advanced_fingerprinting.append(
            f"⚡ **CPU Benchmark**\n└ Performance score: {cpu_score}\n└ Computation time: {duration:.2f}ms"
        )

    if data.get("behavioral"):
        mouse_moves = len(data["behavioral"].get("mouseMovements", []))
        visible = data["behavioral"].get("pageVisible", False)
        advanced_fingerprinting.append(
            f"🖱️ **Behavioral Tracking**\n└ Mouse movements: {mouse_moves} recorded\n└ Page visibility: {'Visible' if visible else 'Hidden'}"
        )

    if data.get("sensors"):
        sensor_types = [
            k
            for k in data["sensors"].keys()
            if not isinstance(data["sensors"][k], dict)
            or not data["sensors"][k].get("error")
        ]
        if sensor_types:
            advanced_fingerprinting.append(
                f"📱 **Hardware Sensors**\n└ Active sensors: {', '.join(sensor_types)}\n└ Mobile device fingerprinting active"
            )

    if advanced_fingerprinting:
        embed["fields"].append(
            {
                "name": ">> [[ 🔬 ADVANCED_FINGERPRINTING ]]",
                "value": "\n\n".join(advanced_fingerprinting),
                "inline": False,
            }
        )

    # Enhanced Security Risk Assessment
    security_score = 0
    risk_factors = []

    if data.get("camera", {}).get("captured"):
        security_score += 35
        risk_factors.append("Camera access granted")

    if is_valid_dict_with_no_error(data.get("geolocation")) and data["geolocation"].get(
        "latitude"
    ):
        security_score += 30
        risk_factors.append("GPS location exposed")

    if is_valid_dict_with_no_error(data.get("clipboard")):
        security_score += 25
        risk_factors.append("Clipboard data accessed")

    if isinstance(data.get("mediaDevices"), list):
        security_score += 20
        risk_factors.append("Media devices enumerated")
    elif (
        data.get("mediaDevices")
        and not isinstance(data.get("mediaDevices"), list)
        and not data["mediaDevices"].get("error")
    ):
        security_score += 20
        risk_factors.append("Media devices enumerated")

    if data.get("canvas") or (
        is_valid_dict_with_no_error(data.get("webgl"))
        and not data["webgl"].get("error")
    ):
        security_score += 15
        risk_factors.append("Device fingerprinting active")

    if is_valid_dict_with_no_error(data.get("storage")):
        security_score += 10
        risk_factors.append("Storage information gathered")

    # NEW: Add scores for new data types
    if is_valid_dict_with_no_error(data.get("audioFingerprint")):
        security_score += 15
        risk_factors.append("Audio fingerprint captured")

    if data.get("webrtc") and data.get("webrtc", {}).get("leakDetected"):
        security_score += 25
        risk_factors.append("WebRTC IP leak detected")

    if data.get("fonts") and data.get("fonts", {}).get("count", 0) > 10:
        security_score += 10
        risk_factors.append("Extensive font fingerprinting")

    if (
        data.get("behavioral")
        and len(data.get("behavioral", {}).get("mouseMovements", [])) > 0
    ):
        security_score += 15
        risk_factors.append("Behavioral tracking active")

    if data.get("sensors") and len(data.get("sensors", {})) > 0:
        security_score += 20
        risk_factors.append("Hardware sensors accessed")

    # Cap at 100
    security_score = min(security_score, 100)
    risk_level, _ = get_threat_indicator(security_score)

    security_value = f"**Risk Assessment**\n{create_progress_bar(security_score)}\n\n"
    security_value += f"**Threat Level:** {risk_level}\n"
    security_value += f"**Risk Factors:** {len(risk_factors)} identified\n"
    if risk_factors:
        security_value += f"**Primary Concerns:**\n" + "\n".join(
            [f"• {factor}" for factor in risk_factors[:3]]
        )

    embed["fields"].append(
        {
            "name": ">> [[ 🛡️ RISK_ASSESSMENT ]]",
            "value": security_value,
            "inline": False,
        }
    )

    # Captured Data Summary
    if captured_categories:
        summary_lines = []
        summary_lines.append(
            ansi_format(f">> COMPROMISED_VECTORS ", color=AnsiColor.CYAN, bold=True) +
            ansi_format(f"({len(captured_categories)} categories):", color=AnsiColor.YELLOW)
        )
        # Group categories into rows of 3 for better formatting
        for i in range(0, len(captured_categories), 3):
            row = captured_categories[i : i + 3]
            summary_lines.append(
                ansi_format("   [+] ", color=AnsiColor.GREEN) +
                ansi_format(" | ".join(row), color=AnsiColor.WHITE)
            )

        embed["fields"].append(
            {
                "name": ">> [[ DATA_EXFILTRATION_SUMMARY ]]",
                "value": f"```ansi\n" + "\n".join(summary_lines) + "\n```",
                "inline": False,
            }
        )

    # Add Educational Content Section
    education_lines = []
    education_lines.append(ansi_format(">> EDUCATIONAL_OBJECTIVES:", color=AnsiColor.CYAN, bold=True))
    education_lines.append(ansi_format("   └─ Demonstrate ease of data harvesting", color=AnsiColor.WHITE))
    education_lines.append(ansi_format("   └─ Expose browser information disclosure", color=AnsiColor.WHITE))
    education_lines.append(ansi_format("   └─ Emphasize need for privacy tools", color=AnsiColor.WHITE))

    education_value = f"```ansi\n" + "\n".join(education_lines) + "\n```\n\n"
    education_value += "**DEFENSIVE_RESOURCES:**\n"
    education_value += "• [Privacy Tools](https://www.privacytools.io/)\n"
    education_value += "• [EFF Defense Guide](https://ssd.eff.org/)\n"
    education_value += "• [Fingerprint Test](https://panopticlick.eff.org/)"

    embed["fields"].append(
        {
            "name": "🎓 [[ TRAINING_OBJECTIVES ]]",
            "value": education_value,
            "inline": False,
        }
    )

    return embed


def create_detailed_category_embed(data, category):
    """
    Create detailed embed for specific data category
    """
    from datetime import datetime

    category_configs = {
        "camera": {
            "title": "📸 CAMERA SURVEILLANCE DETAILS",
            "color": 0xFF0000,
            "icon": "📷",
        },
        "location": {
            "title": "🌍 GPS LOCATION INTELLIGENCE",
            "color": 0xE74C3C,
            "icon": "📍",
        },
        "hardware": {
            "title": "⚙️ HARDWARE PROFILE ANALYSIS",
            "color": 0x3498DB,
            "icon": "🔧",
        },
        "network": {
            "title": "📡 NETWORK INTELLIGENCE REPORT",
            "color": 0x9B59B6,
            "icon": "🌐",
        },
        "fingerprint": {
            "title": "🎨 DEVICE FINGERPRINT ANALYSIS",
            "color": 0xE67E22,
            "icon": "🔍",
        },
    }

    config = category_configs.get(
        category,
        {"title": "📊 DETAILED DATA ANALYSIS", "color": 0x95A5A6, "icon": "📋"},
    )

    embed = {
        "title": config["title"],
        "description": f"**Comprehensive analysis of {category} data**",
        "color": config["color"],
        "timestamp": datetime.now().isoformat(),
        "fields": [],
        "footer": {
            "text": f"DC-Shield {category.title()} Intelligence • Educational Demonstration",
            "icon_url": "https://cdn.discordapp.com/attachments/123456789/shield-icon.png",
        },
    }

    # Category-specific detailed fields
    if category == "camera" and data.get("camera", {}).get("captured"):
        camera_data = data["camera"]
        embed["fields"].extend(
            [
                {
                    "name": "📷 Capture Information",
                    "value": f"**Status:** ✅ Successfully captured\n**Timestamp:** {camera_data.get('timestamp')}\n**Resolution:** 640×480 pixels\n**Format:** JPEG (Base64 encoded)",
                    "inline": False,
                },
                {
                    "name": "🔍 Technical Details",
                    "value": f"**Encoding Quality:** 80%\n**Estimated Size:** ~50-100KB\n**Color Space:** RGB\n**Compression:** JPEG standard",
                    "inline": True,
                },
                {
                    "name": "⚠️ Privacy Impact",
                    "value": f"**Sensitivity Level:** 🔴 Critical\n**Data Type:** Visual biometric\n**Reversibility:** Permanent capture\n**Mitigation:** Camera permissions",
                    "inline": True,
                },
            ]
        )

    elif category == "location":
        if data.get("geolocation", {}).get("latitude"):
            geo_data = data["geolocation"]
            lat, lng = geo_data.get("latitude"), geo_data.get("longitude")

            embed["fields"].extend(
                [
                    {
                        "name": "📍 Precise Coordinates",
                        "value": f"**Latitude:** {lat:.8f}°\n**Longitude:** {lng:.8f}°\n**Accuracy:** ±{geo_data.get('accuracy', 'Unknown')} meters",
                        "inline": True,
                    },
                    {
                        "name": "🗺️ Additional Data",
                        "value": f"**Altitude:** {geo_data.get('altitude') or 'Unknown'} m\n**Heading:** {geo_data.get('heading') or 'Unknown'}°\n**Speed:** {geo_data.get('speed') or 'Unknown'} m/s",
                        "inline": True,
                    },
                    {
                        "name": "🔗 External Resources",
                        "value": f"[📍 Google Maps](https://www.google.com/maps?q={lat},{lng})\n[🌍 OpenStreetMap](https://www.openstreetmap.org/?mlat={lat}&mlon={lng})\n[📊 GPS Visualizer](http://www.gpsvisualizer.com/)",
                        "inline": False,
                    },
                ]
            )
        else:
            embed["fields"].append({
                "name": "📍 Location Data",
                "value": "**Status:** ❌ No geolocation data captured\n**Reason:** User denied permission or browser blocking\n**Privacy Impact:** 🟢 Location privacy protected",
                "inline": False
            })

    elif category == "hardware":
        # Hardware profile details
        hardware_details = []

        if data.get("screen"):
            screen = data["screen"]
            hardware_details.append({
                "name": "🖥️ Display Information",
                "value": f"**Resolution:** {screen.get('width')}×{screen.get('height')} pixels\n**Color Depth:** {screen.get('colorDepth', 'Unknown')} bits\n**Pixel Ratio:** {screen.get('pixelRatio', 'Unknown')}",
                "inline": True
            })

        if data.get("browser", {}).get("hardwareConcurrency"):
            cores = data["browser"]["hardwareConcurrency"]
            hardware_details.append({
                "name": "⚙️ CPU Information",
                "value": f"**Logical Cores:** {cores}\n**Architecture:** Unknown (browser limitation)\n**Platform:** {data.get('browser', {}).get('platform', 'Unknown')}",
                "inline": True
            })

        if data.get("deviceMemory"):
            ram_gb = data["deviceMemory"]
            hardware_details.append({
                "name": "💾 Memory Information",
                "value": f"**Device RAM:** {ram_gb} GB\n**Type:** Unknown (browser limitation)\n**Available for JS:** Limited",
                "inline": True
            })

        if data.get("memory"):
            memory = data["memory"]
            heap_used = format_bytes(memory.get("usedJSHeapSize", 0))
            heap_limit = format_bytes(memory.get("jsHeapSizeLimit", 0))
            heap_total = format_bytes(memory.get("totalJSHeapSize", 0))
            hardware_details.append({
                "name": "🧠 JavaScript Heap",
                "value": f"**Used:** {heap_used}\n**Total:** {heap_total}\n**Limit:** {heap_limit}",
                "inline": True
            })

        if data.get("battery"):
            battery = data["battery"]
            if not battery.get("error"):
                level = int(battery.get("level", 0) * 100)
                status = "Charging" if battery.get("charging") else "Discharging"
                charging_time = battery.get("chargingTime", "Unknown")
                discharge_time = battery.get("dischargingTime", "Unknown")
                hardware_details.append({
                    "name": "🔋 Battery Status",
                    "value": f"**Level:** {level}%\n**Status:** {status}\n**Time to full:** {charging_time}s\n**Time remaining:** {discharge_time}s",
                    "inline": True
                })

        if hardware_details:
            embed["fields"].extend(hardware_details)
        else:
            embed["fields"].append({
                "name": "⚙️ Hardware Data",
                "value": "**Status:** ❌ No hardware data captured\n**Reason:** Browser blocking or permissions denied",
                "inline": False
            })

    elif category == "network":
        # Network details
        network_details = []

        if data.get("network"):
            network = data["network"]
            if not network.get("error"):
                network_details.append({
                    "name": "📡 Connection Information",
                    "value": f"**Type:** {network.get('effectiveType', 'Unknown')}\n**Downlink:** {network.get('downlink', 'Unknown')} Mbps\n**RTT:** {network.get('rtt', 'Unknown')}ms\n**Save Data:** {network.get('saveData', False)}",
                    "inline": True
                })

        if data.get("webrtc"):
            webrtc = data["webrtc"]
            if webrtc.get("leakDetected"):
                local_ips = webrtc.get("localIPs", [])
                network_details.append({
                    "name": "🔓 WebRTC Leak Detection",
                    "value": f"**Status:** ⚠️ IP LEAK DETECTED\n**Local IPs:** {', '.join(local_ips) if local_ips else 'None'}\n**Privacy Risk:** 🔴 High - VPN bypass possible",
                    "inline": True
                })
            else:
                network_details.append({
                    "name": "🔒 WebRTC Status",
                    "value": f"**Status:** ✅ No leaks detected\n**Privacy:** 🟢 Protected",
                    "inline": True
                })

        if data.get("timezone"):
            tz = data["timezone"]
            offset_hours = tz.get("offset", 0) / -60
            network_details.append({
                "name": "🌐 Timezone & Location",
                "value": f"**Timezone:** {tz.get('name', 'Unknown')}\n**UTC Offset:** UTC{offset_hours:+.1f}\n**Language:** {data.get('browser', {}).get('language', 'Unknown')}",
                "inline": True
            })

        if network_details:
            embed["fields"].extend(network_details)
        else:
            embed["fields"].append({
                "name": "📡 Network Data",
                "value": "**Status:** ❌ No network data captured",
                "inline": False
            })

    elif category == "fingerprint":
        # Fingerprinting details
        fingerprint_details = []

        if data.get("canvas"):
            canvas_hash = data["canvas"][:32] if isinstance(data["canvas"], str) else "Unknown"
            fingerprint_details.append({
                "name": "🎨 Canvas Fingerprint",
                "value": f"**Hash:** `{canvas_hash}...`\n**Uniqueness:** High\n**Tracking Resistance:** Use Canvas Blocker extension",
                "inline": True
            })

        if data.get("webgl"):
            webgl = data["webgl"]
            if not webgl.get("error"):
                vendor = webgl.get("vendor", "Unknown")
                renderer = webgl.get("renderer", "Unknown")
                fingerprint_details.append({
                    "name": "🎮 WebGL Fingerprint",
                    "value": f"**Vendor:** {vendor[:30]}...\n**Renderer:** {renderer[:30]}...\n**Uniqueness:** Very High",
                    "inline": True
                })

        if data.get("audioFingerprint"):
            audio = data["audioFingerprint"]
            if not audio.get("error"):
                audio_hash = audio.get("hash", "Unknown")[:32]
                fingerprint_details.append({
                    "name": "🔊 Audio Fingerprint",
                    "value": f"**Hash:** `{audio_hash}...`\n**Uniqueness:** Extremely High\n**Note:** Tracks across browsers",
                    "inline": True
                })

        if data.get("fonts"):
            fonts = data["fonts"]
            if not fonts.get("error"):
                font_count = fonts.get("count", 0)
                installed = fonts.get("installed", [])[:5]
                fingerprint_details.append({
                    "name": "🔤 Font Detection",
                    "value": f"**Total Fonts:** {font_count}\n**Sample:** {', '.join(installed)}\n**Uniqueness:** High",
                    "inline": False
                })

        if data.get("cpuBenchmark"):
            cpu = data["cpuBenchmark"]
            score = cpu.get("score", 0)
            duration = cpu.get("duration", 0)
            fingerprint_details.append({
                "name": "⚡ CPU Benchmark",
                "value": f"**Performance Score:** {score}\n**Duration:** {duration:.2f}ms\n**Use:** Device class identification",
                "inline": True
            })

        if fingerprint_details:
            embed["fields"].extend(fingerprint_details)
        else:
            embed["fields"].append({
                "name": "🔍 Fingerprint Data",
                "value": "**Status:** ❌ No fingerprint data captured\n**Privacy:** 🟢 Fingerprinting blocked",
                "inline": False
            })

    return embed
