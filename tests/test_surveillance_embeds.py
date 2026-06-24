"""
Unit tests for surveillance_embeds.py
Tests Discord embed generation and formatting functions
"""
import pytest
from surveillance_embeds import (
    create_progress_bar,
    format_bytes,
    get_threat_indicator,
    get_security_lesson,
    create_combined_surveillance_embed,
    create_detailed_category_embed,
)


@pytest.mark.unit
class TestUtilityFunctions:
    """Test utility functions for formatting and display"""

    def test_create_progress_bar_empty(self):
        """Test progress bar with 0% completion"""
        result = create_progress_bar(0, length=10)
        assert "░" * 10 in result
        assert "█" not in result
        assert "0%" in result

    def test_create_progress_bar_full(self):
        """Test progress bar with 100% completion"""
        result = create_progress_bar(100, length=10)
        assert "█" * 10 in result
        assert "░" not in result
        assert "100%" in result

    def test_create_progress_bar_half(self):
        """Test progress bar with 50% completion"""
        result = create_progress_bar(50, length=10)
        assert "█" * 5 in result
        assert "░" * 5 in result
        assert "50%" in result

    def test_create_progress_bar_custom_length(self):
        """Test progress bar with custom length"""
        result = create_progress_bar(25, length=20)
        assert "25%" in result
        # Total characters should be 20 (5 filled + 15 empty)

    def test_format_bytes_zero(self):
        """Test formatting zero bytes"""
        assert format_bytes(0) == "0 B"
        assert format_bytes(None) == "0 B"

    def test_format_bytes_small(self):
        """Test formatting small byte values"""
        assert format_bytes(512) == "512.0 B"
        assert format_bytes(1023) == "1023.0 B"

    def test_format_bytes_kilobytes(self):
        """Test formatting kilobytes"""
        assert format_bytes(1024) == "1.0 KB"
        assert format_bytes(2048) == "2.0 KB"

    def test_format_bytes_megabytes(self):
        """Test formatting megabytes"""
        assert format_bytes(1024 * 1024) == "1.0 MB"
        assert format_bytes(1024 * 1024 * 5) == "5.0 MB"

    def test_format_bytes_gigabytes(self):
        """Test formatting gigabytes"""
        assert format_bytes(1024 * 1024 * 1024) == "1.0 GB"

    def test_format_bytes_large(self):
        """Test formatting very large values"""
        assert "TB" in format_bytes(1024 * 1024 * 1024 * 1024)


@pytest.mark.unit
class TestThreatIndicators:
    """Test threat level and indicator functions"""

    def test_get_threat_indicator_minimal(self):
        """Test threat indicator for minimal threat (0-19)"""
        label, color = get_threat_indicator(10)
        assert "MINIMAL_TRACE" in label
        assert color == 0x00AA00  # Dark green

    def test_get_threat_indicator_low(self):
        """Test threat indicator for low threat (20-39)"""
        label, color = get_threat_indicator(30)
        assert "LOW_EXPOSURE" in label
        assert color == 0x00FF00  # Matrix green

    def test_get_threat_indicator_moderate(self):
        """Test threat indicator for moderate threat (40-59)"""
        label, color = get_threat_indicator(50)
        assert "MODERATE_ALERT" in label
        assert color == 0xFFFF00  # Yellow

    def test_get_threat_indicator_high(self):
        """Test threat indicator for high threat (60-79)"""
        label, color = get_threat_indicator(70)
        assert "HIGH_RISK" in label
        assert color == 0xFF4500  # Orange-red

    def test_get_threat_indicator_critical(self):
        """Test threat indicator for critical threat (80-100)"""
        label, color = get_threat_indicator(90)
        assert "CRITICAL_THREAT" in label
        assert color == 0xFF0000  # Red

    def test_get_threat_indicator_boundary_values(self):
        """Test threat indicator at boundary values"""
        # Test boundaries
        assert "MINIMAL_TRACE" in get_threat_indicator(0)[0]
        assert "LOW_EXPOSURE" in get_threat_indicator(20)[0]
        assert "MODERATE_ALERT" in get_threat_indicator(40)[0]
        assert "HIGH_RISK" in get_threat_indicator(60)[0]
        assert "CRITICAL_THREAT" in get_threat_indicator(80)[0]


@pytest.mark.unit
class TestSecurityLessons:
    """Test security lesson retrieval"""

    def test_get_security_lesson_geolocation(self):
        """Test geolocation security lesson"""
        lesson = get_security_lesson("geolocation")
        assert lesson["title"] == "📍 Geolocation Privacy"
        assert "lesson" in lesson
        assert "protection" in lesson
        assert "reference" in lesson

    def test_get_security_lesson_fingerprinting(self):
        """Test fingerprinting security lesson"""
        lesson = get_security_lesson("fingerprinting")
        assert lesson["title"] == "🔍 Browser Fingerprinting"
        assert "Tor Browser" in lesson["protection"]

    def test_get_security_lesson_camera(self):
        """Test camera security lesson"""
        lesson = get_security_lesson("camera")
        assert lesson["title"] == "📸 Camera/Microphone Access"
        assert "getUserMedia" in lesson["lesson"]

    def test_get_security_lesson_vpn_detection(self):
        """Test VPN detection security lesson"""
        lesson = get_security_lesson("vpn_detection")
        assert lesson["title"] == "🛡️ VPN Detection"
        assert "WebRTC" in lesson["reference"]

    def test_get_security_lesson_clipboard(self):
        """Test clipboard security lesson"""
        lesson = get_security_lesson("clipboard")
        assert lesson["title"] == "📋 Clipboard Access"
        assert "Clipboard API" in lesson["reference"]

    def test_get_security_lesson_unknown(self):
        """Test fallback for unknown vulnerability types"""
        lesson = get_security_lesson("unknown_type")
        assert lesson["title"] == "🔒 General Security"
        assert "OWASP" in lesson["reference"]


@pytest.mark.unit
class TestCombinedSurveillanceEmbed:
    """Test combined surveillance embed generation"""

    def test_create_embed_minimal_data(self):
        """Test embed creation with minimal data"""
        data = {}
        embed = create_combined_surveillance_embed(data)

        assert "title" in embed
        assert "SURVEILLANCE PROTOCOL" in embed["title"]
        assert "color" in embed
        assert "fields" in embed
        assert isinstance(embed["fields"], list)

    def test_create_embed_with_screen_data(self):
        """Test embed with screen data"""
        data = {"screen": {"width": 1920, "height": 1080, "colorDepth": 24}}
        embed = create_combined_surveillance_embed(data)

        # Find hardware profile field
        hardware_field = next(
            (f for f in embed["fields"] if "HARDWARE_PROFILE" in f["name"]), None
        )
        assert hardware_field is not None

    def test_create_embed_with_geolocation(self):
        """Test embed with geolocation data"""
        data = {
            "geolocation": {
                "latitude": 40.7128,
                "longitude": -74.0060,
                "accuracy": 10,
            }
        }
        embed = create_combined_surveillance_embed(data)

        # Should have critical alerts section
        critical_field = next(
            (f for f in embed["fields"] if "CRITICAL EXPLOITS" in f["name"]), None
        )
        assert critical_field is not None
        assert "LOCATION" in critical_field["value"]

    def test_create_embed_with_camera_capture(self):
        """Test embed with camera capture"""
        data = {
            "camera": {"captured": True, "timestamp": "2025-10-16T10:00:00"}
        }
        embed = create_combined_surveillance_embed(data)

        # Should have critical alerts
        critical_field = next(
            (f for f in embed["fields"] if "CRITICAL EXPLOITS" in f["name"]), None
        )
        assert critical_field is not None
        assert "CAMERA" in critical_field["value"]

    def test_create_embed_with_clipboard_data(self):
        """Test embed with clipboard data"""
        data = {
            "clipboard": {"content": "sensitive password", "length": 18}
        }
        embed = create_combined_surveillance_embed(data)

        critical_field = next(
            (f for f in embed["fields"] if "CRITICAL EXPLOITS" in f["name"]), None
        )
        assert critical_field is not None
        assert "CLIPBOARD" in critical_field["value"]

    def test_create_embed_with_webrtc_leak(self):
        """Test embed with WebRTC IP leak"""
        data = {
            "webrtc": {
                "leakDetected": True,
                "localIPs": ["192.168.1.100", "10.0.0.50"],
            }
        }
        embed = create_combined_surveillance_embed(data)

        critical_field = next(
            (f for f in embed["fields"] if "CRITICAL EXPLOITS" in f["name"]), None
        )
        assert critical_field is not None
        assert "WEBRTC" in critical_field["value"]

    def test_create_embed_with_audio_fingerprint(self):
        """Test embed with audio fingerprint"""
        data = {
            "audioFingerprint": {"hash": "124.04347657808103"}
        }
        embed = create_combined_surveillance_embed(data)

        critical_field = next(
            (f for f in embed["fields"] if "CRITICAL EXPLOITS" in f["name"]), None
        )
        assert critical_field is not None
        assert "AUDIO FINGERPRINT" in critical_field["value"]

    def test_create_embed_with_device_recognition_new(self):
        """Test embed with new device recognition"""
        data = {}
        recognition_info = {
            "is_returning": False,
            "current_name": "user1",
            "fingerprint": "a3f9d2c1e8b5",
        }
        embed = create_combined_surveillance_embed(data, recognition_info)

        # Should have device recognition field
        recognition_field = next(
            (f for f in embed["fields"] if "NEW DEVICE" in f["name"]), None
        )
        assert recognition_field is not None
        assert "user1" in recognition_field["value"]

    def test_create_embed_with_device_recognition_returning_same_name(self):
        """Test embed with returning device (same name)"""
        data = {}
        recognition_info = {
            "is_returning": True,
            "is_new_name": False,
            "current_name": "user1",
            "visit_count": 3,
            "first_seen": "2025-10-16T10:00:00",
            "last_seen": "2025-10-16T14:00:00",
            "previous_ips": ["192.168.1.100"],
            "fingerprint": "a3f9d2c1e8b5",
        }
        embed = create_combined_surveillance_embed(data, recognition_info)

        recognition_field = next(
            (f for f in embed["fields"] if "RETURNING DEVICE" in f["name"]), None
        )
        assert recognition_field is not None
        assert "user1" in recognition_field["value"]

    def test_create_embed_with_device_recognition_new_identity(self):
        """Test embed with returning device (different name - spoofing)"""
        data = {}
        recognition_info = {
            "is_returning": True,
            "is_new_name": True,
            "current_name": "user2",
            "previous_names": ["user1"],
            "visit_count": 2,
            "first_seen": "2025-10-16T10:00:00",
            "last_seen": "2025-10-16T14:00:00",
            "previous_ips": ["192.168.1.100"],
            "fingerprint": "a3f9d2c1e8b5",
        }
        embed = create_combined_surveillance_embed(data, recognition_info)

        recognition_field = next(
            (f for f in embed["fields"] if "IDENTITY SPOOFING DETECTED" in f["name"]), None
        )
        assert recognition_field is not None
        assert "SPOOFING" in recognition_field["value"]
        assert "user1" in recognition_field["value"]

    def test_create_embed_with_fonts(self):
        """Test embed with font detection"""
        data = {
            "fonts": {
                "count": 50,
                "installed": ["Arial", "Times New Roman", "Courier New"],
            }
        }
        embed = create_combined_surveillance_embed(data)

        # Should have advanced fingerprinting section
        advanced_field = next(
            (f for f in embed["fields"] if "ADVANCED_FINGERPRINTING" in f["name"]),
            None,
        )
        assert advanced_field is not None
        assert "Font" in advanced_field["value"]

    def test_create_embed_with_behavioral_tracking(self):
        """Test embed with behavioral tracking data"""
        data = {
            "behavioral": {
                "mouseMovements": [{"x": 100, "y": 200, "time": 1000}],
                "pageVisible": True,
            }
        }
        embed = create_combined_surveillance_embed(data)

        advanced_field = next(
            (f for f in embed["fields"] if "ADVANCED_FINGERPRINTING" in f["name"]),
            None,
        )
        assert advanced_field is not None
        assert "Behavioral" in advanced_field["value"]

    def test_create_embed_has_educational_section(self):
        """Test that embed always includes educational objectives"""
        data = {}
        embed = create_combined_surveillance_embed(data)

        education_field = next(
            (f for f in embed["fields"] if "TRAINING_OBJECTIVES" in f["name"]), None
        )
        assert education_field is not None
        assert "EDUCATIONAL_OBJECTIVES" in education_field["value"]

    def test_create_embed_has_risk_assessment(self):
        """Test that embed includes risk assessment"""
        data = {}
        embed = create_combined_surveillance_embed(data)

        risk_field = next(
            (f for f in embed["fields"] if "RISK_ASSESSMENT" in f["name"]), None
        )
        assert risk_field is not None

    def test_create_embed_high_risk_score(self):
        """Test risk score calculation with high-risk data"""
        data = {
            "camera": {"captured": True, "timestamp": "2025-10-16T10:00:00"},
            "geolocation": {"latitude": 40.7128, "longitude": -74.0060, "accuracy": 10},
            "clipboard": {"content": "password", "length": 8},
            "audioFingerprint": {"hash": "124.04347657808103"},
            "webrtc": {"leakDetected": True, "localIPs": ["192.168.1.100"]},
            "mediaDevices": [
                {"kind": "videoinput", "label": "Camera"},
                {"kind": "audioinput", "label": "Microphone"}
            ],
            "canvas": "data:image/png;base64,test",
            "webgl": {"vendor": "Google Inc.", "renderer": "ANGLE"},
            "storage": {"quota": 1000000},
            "fonts": {"count": 50, "installed": ["Arial", "Times"]},
            "behavioral": {"mouseMovements": [{"x": 100, "y": 200}], "pageVisible": True},
            "sensors": {"accelerometer": {"x": 0, "y": 0, "z": 9.8}}
        }
        embed = create_combined_surveillance_embed(data)

        # Should have high risk indicators (could be any color, but should have high category count)
        # Check that multiple categories were captured
        assert "color" in embed
        # With all this data, we should have a significant number of categories
        description = embed.get("description", "")
        assert "vectors compromised" in description


@pytest.mark.unit
class TestDetailedCategoryEmbed:
    """Test detailed category embed generation"""

    def test_create_detailed_camera_embed(self):
        """Test detailed camera category embed"""
        data = {
            "camera": {"captured": True, "timestamp": "2025-10-16T10:00:00"}
        }
        embed = create_detailed_category_embed(data, "camera")

        assert "CAMERA" in embed["title"]
        assert embed["color"] == 0xFF0000
        assert len(embed["fields"]) > 0

    def test_create_detailed_location_embed(self):
        """Test detailed location category embed"""
        data = {
            "geolocation": {
                "latitude": 40.7128,
                "longitude": -74.0060,
                "accuracy": 10,
                "altitude": 100,
                "heading": 180,
                "speed": 5,
            }
        }
        embed = create_detailed_category_embed(data, "location")

        assert "LOCATION" in embed["title"]
        assert len(embed["fields"]) > 0
        # Should have map links
        map_field = next((f for f in embed["fields"] if "Google Maps" in f["value"]), None)
        assert map_field is not None

    def test_create_detailed_embed_unknown_category(self):
        """Test detailed embed with unknown category"""
        data = {}
        embed = create_detailed_category_embed(data, "unknown_category")

        assert "DETAILED DATA ANALYSIS" in embed["title"]
        assert "color" in embed
        assert "fields" in embed

    def test_create_detailed_embed_has_footer(self):
        """Test that detailed embed has footer"""
        data = {}
        embed = create_detailed_category_embed(data, "hardware")

        assert "footer" in embed
        assert "DC-Shield" in embed["footer"]["text"]

    def test_create_detailed_embed_has_timestamp(self):
        """Test that detailed embed has timestamp"""
        data = {}
        embed = create_detailed_category_embed(data, "network")

        assert "timestamp" in embed


@pytest.mark.unit
class TestRequestAndImpactFields:
    """Tests for the request-route and victim-facing impact fields."""

    def test_request_field_renders_lure_url(self):
        from surveillance_embeds import _build_request_field
        d = {"_serverRequest": {
            "fullUrl": "https://dc.shield/ticket/victim",
            "method": "GET",
            "referer": "https://discord.gg/x",
        }}
        f = _build_request_field(d)
        assert f is not None
        assert "https://dc.shield/ticket/victim" in f["value"]
        assert "GET" in f["value"]

    def test_request_field_absent_without_data(self):
        from surveillance_embeds import _build_request_field
        assert _build_request_field({}) is None
        assert _build_request_field({"_serverRequest": {}}) is None

    def test_impact_field_lists_real_attacker_takeaways(self):
        from surveillance_embeds import _build_impact_field
        d = {
            "geolocation": {"latitude": 1.0, "longitude": 2.0, "accuracy": 5},
            "camera": {"captured": True},
            "webrtc": {"leakDetected": True, "localIPs": ["10.0.0.1"]},
        }
        f = _build_impact_field(d)
        assert f is not None
        assert "real-world location" in f["value"]
        assert "camera" in f["value"].lower()
        assert "VPN" in f["value"]

    def test_impact_field_absent_when_no_sensitive_data(self):
        from surveillance_embeds import _build_impact_field
        assert _build_impact_field({}) is None

    def test_combined_embed_includes_request_and_impact(self):
        d = {
            "_serverRequest": {"fullUrl": "https://dc.shield/ticket/x", "method": "GET"},
            "geolocation": {"latitude": 1.0, "longitude": 2.0, "accuracy": 5},
        }
        embed = create_combined_surveillance_embed(d, dc_handle="x")
        names = [f["name"] for f in embed["fields"]]
        assert any("Request Route" in n for n in names)
        assert any("Why This Matters" in n for n in names)


@pytest.mark.unit
class TestPhaseACollectors:
    """Phase A — verify the 11 new collector keys render their embed fields."""

    def _fields(self, data):
        embed = create_combined_surveillance_embed(data, dc_handle="t")
        return [f["name"] for f in embed["fields"]]

    def test_ua_client_hints_renders(self):
        names = self._fields({"uaClientHints": {
            "brands": [{"brand": "Chromium", "version": "120"}],
            "fullVersionList": [{"brand": "Chromium", "version": "120.0.6099.71"}],
            "platform": "Windows", "platformVersion": "15.0",
            "architecture": "x86", "bitness": "64",
            "mobile": False, "formFactor": "Desktop",
        }})
        assert any("UA-CH High Entropy" in n for n in names)

    def test_ua_client_hints_error_skips_field(self):
        names = self._fields({"uaClientHints": {"error": "not supported"}})
        assert not any("UA-CH High Entropy" in n for n in names)

    def test_webgpu_renders(self):
        names = self._fields({"webgpu": {
            "vendor": "Google Inc. (Intel)",
            "architecture": "common-3d",
            "device": "Intel(R) UHD",
        }})
        assert any("Hardware Acceleration" in n for n in names)

    def test_drm_renders(self):
        names = self._fields({"drm": {
            "keySystems": {"Widevine": True, "PlayReady": False, "FairPlay": False},
            "codecs": {"H.264": True, "VP9": True, "AV1": False, "HEVC": False, "EAC3": True},
        }})
        assert any("Hardware Acceleration" in n for n in names)

    def test_speech_voices_renders(self):
        names = self._fields({"speechVoices": {
            "count": 3,
            "sample": [
                {"name": "Google US English", "lang": "en-US"},
                {"name": "Google UK English Male", "lang": "en-GB"},
            ],
        }})
        assert any("OS-Level Leaks" in n for n in names)

    def test_keyboard_layout_renders(self):
        names = self._fields({"keyboardLayout": {
            "size": 5, "sample": {"KeyQ": "q", "KeyW": "w", "KeyE": "e", "KeyR": "r"},
        }})
        assert any("Display & Input Capabilities" in n for n in names)

    def test_installed_apps_renders(self):
        names = self._fields({"installedApps": {
            "count": 2,
            "apps": [
                {"id": "com.example.app1", "platform": "play"},
                {"id": "https://app2.com", "platform": "web"},
            ],
        }})
        assert any("OS-Level Leaks" in n for n in names)

    def test_screen_details_is_extended_renders(self):
        names = self._fields({"screenDetails": {"isExtended": True}})
        assert any("Display & Input Capabilities" in n for n in names)

    def test_screen_details_false_still_renders(self):
        names = self._fields({"screenDetails": {"isExtended": False}})
        assert any("Display & Input Capabilities" in n for n in names)

    def test_hardening_signals_renders(self):
        names = self._fields({"hardeningSignals": {
            "sharedArrayBuffer": True,
            "crossOriginIsolated": False,
            "isSecureContext": True,
            "trustedTypes": False,
            "cookieStore": True,
            "storageAccessApi": False,
        }})
        assert any("Hardening Posture" in n for n in names)

    def test_hardening_signals_error_skips_field(self):
        names = self._fields({"hardeningSignals": {"error": "failed"}})
        assert not any("Hardening Posture" in n for n in names)

    def test_media_queries_renders(self):
        names = self._fields({"mediaQueries": {
            "colorSchemeDark": True,
            "reducedMotion": False,
            "hoverCapable": True,
            "finePointer": True,
        }})
        assert any("Display & Input Capabilities" in n for n in names)

    def test_permissions_renders(self):
        names = self._fields({"permissions": {
            "geolocation": "prompt",
            "notifications": "denied",
            "camera": "granted",
            "microphone": "prompt",
        }})
        assert any("Permissions State" in n for n in names)

    def test_permissions_error_skips_field(self):
        names = self._fields({"permissions": {"error": "not supported"}})
        assert not any("Permissions State" in n for n in names)

    def test_navigation_timing_counted(self):
        """navigationTiming has no dedicated field but is counted as a captured vector."""
        data = {"navigationTiming": {
            "type": "navigate",
            "responseStart": 10.5,
            "loadEventEnd": 500.3,
            "transferSize": 2048,
            "domInteractive": 200.1,
        }}
        embed = create_combined_surveillance_embed(data, dc_handle="t")
        vectors_field = next(
            (f for f in embed["fields"] if "Captured Vectors" in f["name"]), None
        )
        assert vectors_field is not None
        assert "Navigation Timing" in vectors_field["value"]

    def test_navigation_timing_error_not_counted(self):
        data = {"navigationTiming": {"error": "no entries"}}
        embed = create_combined_surveillance_embed(data, dc_handle="t")
        vectors_field = next(
            (f for f in embed["fields"] if "Captured Vectors" in f["name"]), None
        )
        if vectors_field:
            assert "Navigation Timing" not in vectors_field["value"]

    def test_all_eleven_keys_together(self):
        """All 11 keys present simultaneously — every expected field renders."""
        data = {
            "uaClientHints": {
                "brands": [{"brand": "Chromium", "version": "120"}],
                "fullVersionList": [{"brand": "Chromium", "version": "120.0"}],
                "platform": "macOS", "platformVersion": "14.0",
                "mobile": False,
            },
            "webgpu": {"vendor": "Apple", "architecture": "common-3d", "device": "Apple M1"},
            "drm": {
                "keySystems": {"Widevine": False, "PlayReady": False, "FairPlay": True},
                "codecs": {"H.264": True, "VP9": False, "AV1": False, "HEVC": True, "EAC3": True},
            },
            "speechVoices": {
                "count": 1,
                "sample": [{"name": "Samantha", "lang": "en-US"}],
            },
            "keyboardLayout": {"size": 3, "sample": {"KeyA": "a", "KeyS": "s", "KeyD": "d"}},
            "installedApps": {
                "count": 1,
                "apps": [{"id": "com.test.app", "platform": "play"}],
            },
            "screenDetails": {"isExtended": False},
            "hardeningSignals": {
                "sharedArrayBuffer": False,
                "crossOriginIsolated": False,
                "isSecureContext": True,
                "trustedTypes": False,
                "cookieStore": True,
                "storageAccessApi": False,
            },
            "mediaQueries": {"colorSchemeDark": True, "hoverCapable": True},
            "permissions": {"geolocation": "prompt", "camera": "denied"},
            "navigationTiming": {
                "type": "navigate", "responseStart": 5.0, "loadEventEnd": 300.0,
                "transferSize": 1024, "domInteractive": 150.0,
            },
        }
        names = self._fields(data)
        expected = [
            "UA-CH High Entropy",
            "Hardware Acceleration",
            "OS-Level Leaks",
            "Display & Input Capabilities",
            "Hardening Posture",
            "Permissions State",
        ]
        for label in expected:
            assert any(label in n for n in names), f"missing field: {label}"


@pytest.mark.unit
class TestPhaseBFields:
    """Phase B — automation, locale, privacy, rare hardware."""

    def _fields(self, data):
        embed = create_combined_surveillance_embed(data, dc_handle="t")
        return [f["name"] for f in embed["fields"]]

    def test_automation_detect_renders(self):
        names = self._fields({"automationDetect": {
            "webdriver": False, "headlessIndicators": ["no_plugins"],
            "jsEngine": "V8", "stackFormat": "v8",
            "uaSpoofed": False, "botScore": 10, "likelyBot": False,
        }})
        assert any("Automation & Spoofing" in n for n in names)

    def test_automation_detect_error_skips(self):
        names = self._fields({"automationDetect": {"error": "failed"}})
        assert not any("Automation & Spoofing" in n for n in names)

    def test_intl_locale_with_islamic_calendar(self):
        from surveillance_embeds import _build_intl_locale_field
        f = _build_intl_locale_field({"intlLocale": {
            "locale": "ar-SA", "calendar": "islamic-umalqura",
            "numberingSystem": "arab", "hourCycle": "h12", "hour12": True,
            "collation": "default", "sensitivity": "variant",
            "pluralCategories": ["one", "other"],
        }})
        assert f is not None
        assert "Saudi Arabia" in f["value"]

    def test_privacy_signals_gpc_enabled(self):
        from surveillance_embeds import _build_privacy_signals_field
        f = _build_privacy_signals_field({"privacySignals": {
            "gpc": True, "dnt": "1", "secGpcHeader": "1",
        }})
        assert f is not None
        assert "opt-out" in f["value"]

    def test_privacy_signals_no_optout(self):
        from surveillance_embeds import _build_privacy_signals_field
        f = _build_privacy_signals_field({"privacySignals": {
            "gpc": False, "dnt": None,
        }})
        assert f is not None
        assert "permitted by default" in f["value"]

    def test_plugins_renders_in_automation_field(self):
        from surveillance_embeds import _build_automation_field
        f = _build_automation_field({"plugins": {
            "count": 3, "names": ["PDF Viewer", "Chrome PDF Viewer"],
            "pdfViewerEnabled": True,
        }})
        assert f is not None
        assert "Plugin fingerprint" in f["value"]

    def test_rare_hardware_authenticator(self):
        from surveillance_embeds import _build_rare_hardware_field
        f = _build_rare_hardware_field({"platformAuthenticator": {
            "platformAuthenticatorAvailable": True,
        }})
        assert f is not None
        assert "Biometric" in f["value"]

    def test_rare_hardware_gamepads(self):
        from surveillance_embeds import _build_rare_hardware_field
        f = _build_rare_hardware_field({"gamepads": {
            "count": 1,
            "gamepads": [{"id": "Xbox Controller", "buttons": 14, "axes": 4}],
        }})
        assert f is not None
        assert "Game controllers" in f["value"]

    def test_rare_hardware_absent(self):
        from surveillance_embeds import _build_rare_hardware_field
        assert _build_rare_hardware_field({}) is None

    def test_total_categories_is_42(self):
        embed = create_combined_surveillance_embed({}, dc_handle="t")
        for f in embed["fields"]:
            if "BREACH OVERVIEW" in f["name"]:
                assert "42" in f["value"]
                return
        assert False, "BREACH OVERVIEW field not found"


@pytest.mark.unit
class TestPhaseCBehavioral:
    """Phase C — real behavioral biometric signals."""

    def test_behavioral_field_renders(self):
        from surveillance_embeds import _build_behavioral_field
        f = _build_behavioral_field({"behavioral": {
            "dwellMs": 4200, "maxScrollPct": 78,
            "mouseMoveCount": 312, "mouseMovements": [{"x": 1, "y": 2, "t": 1000}] * 50,
            "clickCount": 4, "clicks": [{"x": 1, "y": 2, "t": 1000, "button": 0}],
            "keystrokeCount": 28,
            "keypresses": [{"downMs": 1000, "upMs": 1094, "dwellMs": 94, "gapMs": 162}],
            "touchCount": 0,
            "visibilityTransitions": [{"state": "visible", "t": 1000}, {"state": "hidden", "t": 2000}],
            "pageVisible": False, "hasFocus": False, "tabVisibility": "hidden",
        }})
        assert f is not None
        assert "BEHAVIORAL BIOMETRICS" in f["name"]
        assert "4.2s" in f["value"]
        assert "78%" in f["value"]
        assert "timing only" in f["value"]

    def test_behavioral_field_absent_on_error(self):
        from surveillance_embeds import _build_behavioral_field
        assert _build_behavioral_field({"behavioral": {"error": "failed"}}) is None

    def test_behavioral_field_absent_on_empty(self):
        from surveillance_embeds import _build_behavioral_field
        assert _build_behavioral_field({}) is None

    def test_no_raw_key_content_in_any_field(self):
        """The no-content invariant: keystroke content must never appear in any embed field."""
        data = {
            "behavioral": {
                "dwellMs": 5000,
                "keystrokeCount": 3,
                "keypresses": [
                    {"downMs": 1000, "upMs": 1094, "dwellMs": 94, "gapMs": 0},
                    {"downMs": 1100, "upMs": 1180, "dwellMs": 80, "gapMs": 6},
                ],
                "mouseMovements": [{"x": 1, "y": 2, "t": 1000}],
                "mouseMoveCount": 5,
            }
        }
        embed = create_combined_surveillance_embed(data, dc_handle="t")
        forbidden = ["e.key", "e.code", "keyCode", "which", "input.value", "password", "secret"]
        for f in embed["fields"]:
            for word in forbidden:
                assert word not in f.get("value", ""), f"forbidden word '{word}' in field {f['name']}"

    def test_keystroke_risk_score_increase(self):
        """Behavioral with keystrokes should score higher than without."""
        from surveillance_embeds import _build_risk_assessment
        base = _build_risk_assessment({"behavioral": {"mouseMovements": [{"x": 1}]}})
        with_keystrokes = _build_risk_assessment({
            "behavioral": {
                "mouseMovements": [{"x": 1}],
                "keystrokes": [{"downMs": 1, "upMs": 2, "dwellMs": 1, "gapMs": 1}],
                "keystrokeCount": 5,
                "dwellMs": 6000,
            }
        })
        base_score = int(base["value"].split("`")[1].split("/")[0])
        ks_score = int(with_keystrokes["value"].split("`")[1].split("/")[0])
        assert ks_score > base_score


@pytest.mark.unit
class TestPhaseDServerSide:
    """Phase D — server-side ASN, protocol, language fields."""

    def test_asn_field_renders(self):
        from surveillance_embeds import _build_asn_field
        f = _build_asn_field({"_serverAsn": {
            "asn": "AS13335", "number": 13335,
            "organization": "Cloudflare, Inc.", "network": "1.0.0.0/24",
            "ipVersion": 4, "classification": "☁️ Datacenter/CDN",
        }})
        assert f is not None
        assert "AS13335" in f["value"]
        assert "Datacenter" in f["value"]

    def test_asn_field_absent(self):
        from surveillance_embeds import _build_asn_field
        assert _build_asn_field({}) is None

    def test_protocol_field_renders(self):
        from surveillance_embeds import _build_protocol_field
        f = _build_protocol_field({"_serverProtocol": {
            "proxyChainDepth": 2, "cloudflareEdge": True,
            "cfRay": "89abc123", "protoConsistency": True,
            "schemeObserved": "https", "ipSource": "CF-Connecting-IP",
            "xffConsistent": True,
        }})
        assert f is not None
        assert "Protocol Posture" in f["name"]
        assert "2` hop" in f["value"]

    def test_protocol_field_mismatch_warning(self):
        from surveillance_embeds import _build_protocol_field
        f = _build_protocol_field({"_serverProtocol": {
            "proxyChainDepth": 1, "protoConsistency": False,
            "schemeObserved": "http",
        }})
        assert f is not None
        assert "mismatch" in f["value"].lower()

    def test_protocol_field_absent(self):
        from surveillance_embeds import _build_protocol_field
        assert _build_protocol_field({}) is None

    def test_language_field_renders(self):
        from surveillance_embeds import _build_language_field
        f = _build_language_field({"_serverLanguage": {
            "primary": "en-US", "primaryLanguage": "en", "region": "US",
            "script": None,
            "languages": [{"tag": "en-US", "q": 1.0}, {"tag": "de", "q": 0.8}],
            "count": 2, "entropyBits": 0.72,
            "geoMismatch": False, "geoCountryCode": "US",
        }})
        assert f is not None
        assert "en-US" in f["value"]
        assert "consistent" in f["value"]

    def test_language_field_mismatch(self):
        from surveillance_embeds import _build_language_field
        f = _build_language_field({"_serverLanguage": {
            "primary": "ru-RU", "primaryLanguage": "ru", "region": "RU",
            "languages": [{"tag": "ru-RU", "q": 1.0}],
            "count": 1, "entropyBits": 0.0,
            "geoMismatch": True, "geoCountryCode": "US",
        }})
        assert f is not None
        assert "mismatch" in f["value"].lower()

    def test_language_field_absent(self):
        from surveillance_embeds import _build_language_field
        assert _build_language_field({}) is None

    def test_all_three_server_fields_in_combined_embed(self):
        data = {
            "_serverAsn": {"asn": "AS13335", "organization": "Cloudflare",
                           "classification": "☁️ Datacenter/CDN", "network": "1.0.0.0/24"},
            "_serverProtocol": {"proxyChainDepth": 1, "schemeObserved": "https",
                                "protoConsistency": True, "ipSource": "CF-Connecting-IP"},
            "_serverLanguage": {"primary": "en-US", "primaryLanguage": "en",
                                 "region": "US", "count": 1, "entropyBits": 0.0,
                                 "geoMismatch": False},
        }
        names = [f["name"] for f in create_combined_surveillance_embed(data, dc_handle="t")["fields"]]
        assert any("ASN / Hosting" in n for n in names)
        assert any("Protocol Posture" in n for n in names)
        assert any("Language Profile" in n for n in names)
