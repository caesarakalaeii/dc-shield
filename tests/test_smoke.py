"""
Smoke tests for DC-Shield
Quick tests to ensure critical functionality works before deployment
"""
import pytest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.mark.unit
class TestImports:
    """Test that all modules can be imported without errors"""

    def test_import_device_tracker(self):
        """Test device_tracker module imports"""
        import device_tracker
        assert hasattr(device_tracker, 'DeviceTracker')
        assert hasattr(device_tracker, 'get_tracker')

    def test_import_surveillance_embeds(self):
        """Test surveillance_embeds module imports"""
        import surveillance_embeds
        assert hasattr(surveillance_embeds, 'create_combined_surveillance_embed')
        assert hasattr(surveillance_embeds, 'create_detailed_category_embed')
        assert hasattr(surveillance_embeds, 'get_threat_indicator')

    def test_import_logger(self):
        """Test logger module imports"""
        import logger
        assert hasattr(logger, 'Logger')

    def test_import_json_handler(self):
        """Test json_handler module imports"""
        import json_handler
        assert hasattr(json_handler, 'read_json_file')


@pytest.mark.unit
class TestCriticalFunctions:
    """Test that critical functions execute without crashing"""

    def test_device_tracker_instantiation(self):
        """Test DeviceTracker can be instantiated"""
        from device_tracker import DeviceTracker
        import tempfile

        fd, temp_path = tempfile.mkstemp(suffix=".json")
        os.close(fd)

        try:
            tracker = DeviceTracker(storage_file=temp_path)
            assert tracker is not None
            assert hasattr(tracker, 'generate_fingerprint')
            assert hasattr(tracker, 'check_device')
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_embed_generation_minimal(self):
        """Test embed generation with minimal data doesn't crash"""
        from surveillance_embeds import create_combined_surveillance_embed

        embed = create_combined_surveillance_embed({})
        assert isinstance(embed, dict)
        assert "title" in embed
        assert "color" in embed
        assert "fields" in embed

    def test_fingerprint_generation(self):
        """Test fingerprint generation works"""
        from device_tracker import DeviceTracker
        import tempfile

        fd, temp_path = tempfile.mkstemp(suffix=".json")
        os.close(fd)

        try:
            tracker = DeviceTracker(storage_file=temp_path)
            device_info = {
                "browser_family": "Chrome",
                "os_family": "Windows",
            }

            fingerprint = tracker.generate_fingerprint(device_info)
            assert isinstance(fingerprint, str)
            assert len(fingerprint) == 64  # SHA256 hash length
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)


@pytest.mark.unit
class TestConfiguration:
    """Test configuration and setup"""

    def test_pytest_config_exists(self):
        """Test pytest configuration file exists"""
        config_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "pytest.ini"
        )
        assert os.path.exists(config_path)

    def test_requirements_exist(self):
        """Test requirements.txt exists"""
        req_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "requirements.txt"
        )
        assert os.path.exists(req_path)

    def test_requirements_has_test_deps(self):
        """Test requirements includes test dependencies"""
        req_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "requirements.txt"
        )
        with open(req_path, 'r') as f:
            content = f.read()

        assert "pytest" in content
        assert "pytest-asyncio" in content
        assert "pytest-cov" in content


@pytest.mark.unit
class TestDataValidation:
    """Test data validation and sanitization"""

    def test_device_info_sanitization(self):
        """Test device info is properly sanitized"""
        from device_tracker import DeviceTracker
        import tempfile

        fd, temp_path = tempfile.mkstemp(suffix=".json")
        os.close(fd)

        try:
            tracker = DeviceTracker(storage_file=temp_path)
            device_info = {
                "browser_family": "Chrome",
                "os_family": "Windows",
                "sensitive_field": "should_not_be_stored",
            }

            sanitized = tracker._sanitize_device_info(device_info)
            assert "browser_family" in sanitized
            assert "sensitive_field" not in sanitized
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_threat_indicator_returns_valid_color(self):
        """Test threat indicators return valid hex colors"""
        from surveillance_embeds import get_threat_indicator

        for score in [0, 20, 40, 60, 80, 100]:
            label, color = get_threat_indicator(score)
            assert isinstance(label, str)
            assert isinstance(color, int)
            assert 0 <= color <= 0xFFFFFF  # Valid hex color


@pytest.mark.unit
class TestErrorHandling:
    """Test error handling in critical paths"""

    def test_device_tracker_handles_missing_file(self):
        """Test DeviceTracker handles missing history file gracefully"""
        from device_tracker import DeviceTracker

        tracker = DeviceTracker(storage_file="/nonexistent/path/file.json")
        assert tracker is not None
        assert len(tracker.device_history) == 0

    def test_embed_handles_malformed_data(self):
        """Test embed generation handles malformed data"""
        from surveillance_embeds import create_combined_surveillance_embed

        # Various malformed data scenarios
        test_cases = [
            None,  # This will fail, but let's test dict types
            {},
            {"invalid": "data"},
            {"geolocation": None},
            {"camera": {"captured": "not_a_bool"}},
        ]

        for data in test_cases:
            if data is None:
                continue
            try:
                embed = create_combined_surveillance_embed(data)
                assert isinstance(embed, dict)
            except Exception as e:
                pytest.fail(f"Embed generation failed with data {data}: {e}")

    def test_fingerprint_with_missing_fields(self):
        """Test fingerprint generation with missing fields"""
        from device_tracker import DeviceTracker
        import tempfile

        fd, temp_path = tempfile.mkstemp(suffix=".json")
        os.close(fd)

        try:
            tracker = DeviceTracker(storage_file=temp_path)

            # Empty device info
            fingerprint1 = tracker.generate_fingerprint({})
            assert isinstance(fingerprint1, str)
            assert len(fingerprint1) == 64

            # Partial device info
            fingerprint2 = tracker.generate_fingerprint({"browser_family": "Chrome"})
            assert isinstance(fingerprint2, str)
            assert len(fingerprint2) == 64
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)
