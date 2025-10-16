"""
Shared pytest fixtures for DC-Shield test suite
"""
import pytest
import json
import os
import tempfile
from unittest.mock import Mock, AsyncMock
from device_tracker import DeviceTracker


@pytest.fixture
def temp_device_history():
    """Create a temporary device history file for testing"""
    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    yield path
    # Cleanup
    if os.path.exists(path):
        os.remove(path)


@pytest.fixture
def device_tracker(temp_device_history):
    """Create a DeviceTracker instance with temporary storage"""
    return DeviceTracker(storage_file=temp_device_history)


@pytest.fixture
def sample_device_info():
    """Sample device information for testing"""
    return {
        "browser_family": "Chrome",
        "browser_version": "120.0.0",
        "os_family": "Windows",
        "os_version": "10",
        "is_mobile": False,
        "is_tablet": False,
        "is_pc": True,
        "sec_ch_device_memory": "8",
        "sec_ch_ua_arch": "x86",
        "sec_ch_ua_bitness": "64",
        "sec_ch_dpr": "1",
        "sec_ch_viewport_width": "1920",
        "sec_ch_viewport_height": "1080",
        "accept_language": "en-US,en;q=0.9",
    }


@pytest.fixture
def sample_advanced_data():
    """Sample advanced fingerprinting data for testing"""
    return {
        "canvas": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==",
        "webgl": {
            "vendor": "Google Inc. (Intel)",
            "renderer": "ANGLE (Intel, Intel(R) UHD Graphics 620 Direct3D11 vs_5_0 ps_5_0)",
            "unmaskedVendor": "Intel Inc.",
            "unmaskedRenderer": "Intel(R) UHD Graphics 620",
            "version": "WebGL 2.0",
        },
        "audioFingerprint": {
            "hash": "124.04347657808103",
            "error": None,
        },
        "screen": {
            "width": 1920,
            "height": 1080,
            "colorDepth": 24,
            "pixelRatio": 1,
        },
        "fonts": {
            "installed": ["Arial", "Times New Roman", "Courier New"],
            "error": None,
        },
        "timezone": {
            "name": "America/New_York",
            "offset": -300,
        },
        "memory": {
            "jsHeapSizeLimit": 2172649472,
        },
    }


@pytest.fixture
def mock_discord_webhook():
    """Mock Discord webhook for testing"""
    return Mock()


@pytest.fixture
def mock_quart_request():
    """Mock Quart request object"""
    mock_request = AsyncMock()
    mock_request.headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "X-Forwarded-For": "192.168.1.100",
        "Accept-Language": "en-US,en;q=0.9",
    }
    mock_request.json = AsyncMock(return_value={})
    return mock_request
