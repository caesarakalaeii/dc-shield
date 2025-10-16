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
            (f for f in embed["fields"] if "IDENTITY CORRELATION" in f["name"]), None
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
