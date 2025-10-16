"""
Unit tests for device_tracker.py
Tests fingerprint generation, device recognition, and history tracking
"""
import pytest
import json
import os
from device_tracker import DeviceTracker, get_tracker


@pytest.mark.unit
class TestDeviceTracker:
    """Test suite for DeviceTracker class"""

    def test_initialization(self, temp_device_history):
        """Test DeviceTracker initialization"""
        tracker = DeviceTracker(storage_file=temp_device_history)
        assert tracker.storage_file == temp_device_history
        assert isinstance(tracker.device_history, dict)
        assert len(tracker.device_history) == 0

    def test_generate_fingerprint_basic(self, device_tracker, sample_device_info):
        """Test fingerprint generation with basic device info"""
        fingerprint = device_tracker.generate_fingerprint(sample_device_info)

        # Should return a SHA256 hash (64 hex characters)
        assert isinstance(fingerprint, str)
        assert len(fingerprint) == 64
        assert all(c in "0123456789abcdef" for c in fingerprint)

    def test_generate_fingerprint_consistent(self, device_tracker, sample_device_info):
        """Test that same device info produces same fingerprint"""
        fingerprint1 = device_tracker.generate_fingerprint(sample_device_info)
        fingerprint2 = device_tracker.generate_fingerprint(sample_device_info)

        assert fingerprint1 == fingerprint2

    def test_generate_fingerprint_unique(self, device_tracker, sample_device_info):
        """Test that different device info produces different fingerprints"""
        fingerprint1 = device_tracker.generate_fingerprint(sample_device_info)

        # Change one value
        modified_info = sample_device_info.copy()
        modified_info["browser_version"] = "121.0.0"
        fingerprint2 = device_tracker.generate_fingerprint(modified_info)

        assert fingerprint1 != fingerprint2

    def test_generate_fingerprint_with_advanced_data(
        self, device_tracker, sample_device_info, sample_advanced_data
    ):
        """Test fingerprint generation with advanced data"""
        fingerprint = device_tracker.generate_fingerprint(
            sample_device_info, sample_advanced_data
        )

        assert isinstance(fingerprint, str)
        assert len(fingerprint) == 64

    def test_advanced_data_affects_fingerprint(
        self, device_tracker, sample_device_info, sample_advanced_data
    ):
        """Test that advanced data changes the fingerprint"""
        fingerprint_basic = device_tracker.generate_fingerprint(sample_device_info)
        fingerprint_advanced = device_tracker.generate_fingerprint(
            sample_device_info, sample_advanced_data
        )

        assert fingerprint_basic != fingerprint_advanced

    def test_check_device_new_device(
        self, device_tracker, sample_device_info, sample_advanced_data
    ):
        """Test checking a new device"""
        fingerprint = device_tracker.generate_fingerprint(
            sample_device_info, sample_advanced_data
        )

        is_returning, info = device_tracker.check_device(
            fingerprint=fingerprint,
            current_name="user1",
            ip_address="192.168.1.100",
            device_info=sample_device_info,
            advanced_data=sample_advanced_data,
        )

        assert is_returning is False
        assert info["is_returning"] is False
        assert info["current_name"] == "user1"
        assert "fingerprint" in info

    def test_check_device_returning_same_name(
        self, device_tracker, sample_device_info, sample_advanced_data
    ):
        """Test checking a returning device with same name"""
        fingerprint = device_tracker.generate_fingerprint(
            sample_device_info, sample_advanced_data
        )

        # First visit
        device_tracker.check_device(
            fingerprint=fingerprint,
            current_name="user1",
            ip_address="192.168.1.100",
            device_info=sample_device_info,
            advanced_data=sample_advanced_data,
        )

        # Second visit - same name
        is_returning, info = device_tracker.check_device(
            fingerprint=fingerprint,
            current_name="user1",
            ip_address="192.168.1.100",
            device_info=sample_device_info,
            advanced_data=sample_advanced_data,
        )

        assert is_returning is True
        assert info["is_returning"] is True
        assert info["is_new_name"] is False
        assert info["current_name"] == "user1"
        assert info["visit_count"] == 2

    def test_check_device_returning_new_name(
        self, device_tracker, sample_device_info, sample_advanced_data
    ):
        """Test checking a returning device with different name (identity spoofing)"""
        fingerprint = device_tracker.generate_fingerprint(
            sample_device_info, sample_advanced_data
        )

        # First visit
        device_tracker.check_device(
            fingerprint=fingerprint,
            current_name="user1",
            ip_address="192.168.1.100",
            device_info=sample_device_info,
            advanced_data=sample_advanced_data,
        )

        # Second visit - different name
        is_returning, info = device_tracker.check_device(
            fingerprint=fingerprint,
            current_name="user2",
            ip_address="192.168.1.100",
            device_info=sample_device_info,
            advanced_data=sample_advanced_data,
        )

        assert is_returning is True
        assert info["is_returning"] is True
        assert info["is_new_name"] is True
        assert info["current_name"] == "user2"
        assert "user1" in info["previous_names"]
        assert info["visit_count"] == 2

    def test_ip_address_tracking(
        self, device_tracker, sample_device_info, sample_advanced_data
    ):
        """Test that IP addresses are tracked correctly"""
        fingerprint = device_tracker.generate_fingerprint(
            sample_device_info, sample_advanced_data
        )

        # Visit from first IP
        device_tracker.check_device(
            fingerprint=fingerprint,
            current_name="user1",
            ip_address="192.168.1.100",
            device_info=sample_device_info,
            advanced_data=sample_advanced_data,
        )

        # Visit from second IP
        is_returning, info = device_tracker.check_device(
            fingerprint=fingerprint,
            current_name="user1",
            ip_address="10.0.0.50",
            device_info=sample_device_info,
            advanced_data=sample_advanced_data,
        )

        assert "192.168.1.100" in info["previous_ips"]
        assert "10.0.0.50" in info["previous_ips"]

    def test_visit_history_tracking(
        self, device_tracker, sample_device_info, sample_advanced_data
    ):
        """Test that visit history is recorded"""
        fingerprint = device_tracker.generate_fingerprint(
            sample_device_info, sample_advanced_data
        )

        # Multiple visits
        for i in range(3):
            device_tracker.check_device(
                fingerprint=fingerprint,
                current_name=f"user{i}",
                ip_address="192.168.1.100",
                device_info=sample_device_info,
                advanced_data=sample_advanced_data,
            )

        # Check history
        is_returning, info = device_tracker.check_device(
            fingerprint=fingerprint,
            current_name="user3",
            ip_address="192.168.1.100",
            device_info=sample_device_info,
            advanced_data=sample_advanced_data,
        )

        assert info["visit_count"] == 4
        assert len(info["visit_history"]) <= 5  # Only last 5 shown

    def test_persistence_save_and_load(
        self, temp_device_history, sample_device_info, sample_advanced_data
    ):
        """Test that device history is persisted to file"""
        # Create tracker and add a device
        tracker1 = DeviceTracker(storage_file=temp_device_history)
        fingerprint = tracker1.generate_fingerprint(
            sample_device_info, sample_advanced_data
        )
        tracker1.check_device(
            fingerprint=fingerprint,
            current_name="user1",
            ip_address="192.168.1.100",
            device_info=sample_device_info,
            advanced_data=sample_advanced_data,
        )

        # Create new tracker instance (simulates restart)
        tracker2 = DeviceTracker(storage_file=temp_device_history)

        # Check that data was loaded
        assert fingerprint in tracker2.device_history
        assert "user1" in tracker2.device_history[fingerprint]["names"]

    def test_get_statistics_empty(self, device_tracker):
        """Test statistics for empty tracker"""
        stats = device_tracker.get_statistics()

        assert stats["total_unique_devices"] == 0
        assert stats["total_visits"] == 0
        assert stats["returning_devices"] == 0
        assert stats["devices_with_multiple_names"] == 0
        assert stats["new_devices"] == 0

    def test_get_statistics_with_devices(
        self, device_tracker, sample_device_info, sample_advanced_data
    ):
        """Test statistics with multiple devices"""
        # Add first device with 2 visits (same name)
        fp1 = device_tracker.generate_fingerprint(sample_device_info, sample_advanced_data)
        device_tracker.check_device(
            fp1, "user1", "192.168.1.100", sample_device_info, sample_advanced_data
        )
        device_tracker.check_device(
            fp1, "user1", "192.168.1.100", sample_device_info, sample_advanced_data
        )

        # Add second device with 3 visits (different names)
        modified_info = sample_device_info.copy()
        modified_info["browser_version"] = "121.0.0"
        fp2 = device_tracker.generate_fingerprint(modified_info, sample_advanced_data)
        device_tracker.check_device(
            fp2, "user2", "192.168.1.101", modified_info, sample_advanced_data
        )
        device_tracker.check_device(
            fp2, "user3", "192.168.1.101", modified_info, sample_advanced_data
        )
        device_tracker.check_device(
            fp2, "user4", "192.168.1.101", modified_info, sample_advanced_data
        )

        # Add third device with 1 visit
        modified_info2 = sample_device_info.copy()
        modified_info2["os_version"] = "11"
        fp3 = device_tracker.generate_fingerprint(modified_info2, sample_advanced_data)
        device_tracker.check_device(
            fp3, "user5", "192.168.1.102", modified_info2, sample_advanced_data
        )

        stats = device_tracker.get_statistics()

        assert stats["total_unique_devices"] == 3
        assert stats["total_visits"] == 6  # 2 + 3 + 1
        assert stats["returning_devices"] == 2  # fp1 and fp2 have > 1 visit
        assert stats["devices_with_multiple_names"] == 1  # Only fp2
        assert stats["new_devices"] == 1  # Only fp3

    def test_sanitize_device_info(self, device_tracker, sample_device_info):
        """Test that device info is sanitized before storage"""
        sanitized = device_tracker._sanitize_device_info(sample_device_info)

        # Check that only safe fields are included
        assert "browser_family" in sanitized
        assert "os_family" in sanitized
        assert "is_mobile" in sanitized

        # Check that sensitive fields are excluded
        assert "sec_ch_device_memory" not in sanitized
        assert "accept_language" not in sanitized

    def test_visit_history_limit(
        self, device_tracker, sample_device_info, sample_advanced_data
    ):
        """Test that visit history is limited to last 20 entries"""
        fingerprint = device_tracker.generate_fingerprint(
            sample_device_info, sample_advanced_data
        )

        # Add 25 visits
        for i in range(25):
            device_tracker.check_device(
                fingerprint=fingerprint,
                current_name="user1",
                ip_address="192.168.1.100",
                device_info=sample_device_info,
                advanced_data=sample_advanced_data,
            )

        # Check that only 20 are stored
        device_record = device_tracker.device_history[fingerprint]
        assert len(device_record["visit_history"]) == 20


@pytest.mark.unit
def test_get_tracker_singleton():
    """Test that get_tracker returns singleton instance"""
    tracker1 = get_tracker()
    tracker2 = get_tracker()

    assert tracker1 is tracker2
