"""
Device Tracking and Recognition System for DC-Shield
Educational tool for demonstrating persistent device fingerprinting across visits
"""

import hashlib
import json
import os
from datetime import datetime
from typing import Dict, List, Optional, Tuple


class DeviceTracker:
    """Tracks and identifies returning devices using browser fingerprinting"""

    def __init__(self, storage_file="device_history.json"):
        """
        Initialize the device tracker with persistent storage

        Args:
            storage_file: Path to JSON file for storing device history
        """
        self.storage_file = storage_file
        self.device_history = self._load_history()

    def _load_history(self) -> Dict:
        """Load device history from persistent storage"""
        if os.path.exists(self.storage_file):
            try:
                with open(self.storage_file, "r") as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                print(f"Warning: Could not load device history: {e}")
                return {}
        return {}

    def _save_history(self):
        """Save device history to persistent storage"""
        try:
            with open(self.storage_file, "w") as f:
                json.dump(self.device_history, f, indent=2, default=str)
        except IOError as e:
            print(f"Error: Could not save device history: {e}")

    def generate_fingerprint(
        self, device_info: Dict, advanced_data: Optional[Dict] = None
    ) -> str:
        """
        Generate a unique device fingerprint from collected data

        Args:
            device_info: Basic device information from HTTP headers
            advanced_data: Optional advanced fingerprinting data (canvas, webgl, etc.)

        Returns:
            SHA256 hash representing the device fingerprint
        """
        # Combine stable identifiers for fingerprinting
        fingerprint_components = []

        # Browser and OS (fairly stable)
        fingerprint_components.append(device_info.get("browser_family", ""))
        fingerprint_components.append(device_info.get("browser_version", ""))
        fingerprint_components.append(device_info.get("os_family", ""))
        fingerprint_components.append(device_info.get("os_version", ""))

        # Hardware hints (very stable)
        fingerprint_components.append(
            device_info.get("sec_ch_device_memory", "unknown")
        )
        fingerprint_components.append(device_info.get("sec_ch_ua_arch", "unknown"))
        fingerprint_components.append(device_info.get("sec_ch_ua_bitness", "unknown"))
        fingerprint_components.append(device_info.get("sec_ch_dpr", "unknown"))

        # Screen information (stable)
        fingerprint_components.append(
            device_info.get("sec_ch_viewport_width", "unknown")
        )
        fingerprint_components.append(
            device_info.get("sec_ch_viewport_height", "unknown")
        )

        # Language and timezone (fairly stable)
        fingerprint_components.append(device_info.get("accept_language", ""))

        # Add advanced fingerprinting data if available
        if advanced_data:
            # Canvas fingerprint (very unique and persistent)
            if advanced_data.get("canvas"):
                fingerprint_components.append(str(advanced_data["canvas"]))

            # WebGL fingerprint (GPU-based, very persistent)
            if advanced_data.get("webgl") and not advanced_data["webgl"].get("error"):
                webgl = advanced_data["webgl"]
                fingerprint_components.append(webgl.get("vendor", ""))
                fingerprint_components.append(webgl.get("renderer", ""))
                fingerprint_components.append(
                    str(webgl.get("unmaskedVendor", ""))
                )  # Very identifying
                fingerprint_components.append(str(webgl.get("unmaskedRenderer", "")))

            # Audio fingerprint (hardware-based, extremely persistent)
            if advanced_data.get("audioFingerprint") and not advanced_data[
                "audioFingerprint"
            ].get("error"):
                fingerprint_components.append(
                    advanced_data["audioFingerprint"].get("hash", "")
                )

            # Screen details (stable)
            if advanced_data.get("screen"):
                screen = advanced_data["screen"]
                fingerprint_components.append(str(screen.get("width", "")))
                fingerprint_components.append(str(screen.get("height", "")))
                fingerprint_components.append(str(screen.get("colorDepth", "")))
                fingerprint_components.append(str(screen.get("pixelRatio", "")))

            # Fonts (fairly stable, changes with software installs)
            if advanced_data.get("fonts") and not advanced_data["fonts"].get("error"):
                fonts = advanced_data["fonts"].get("installed", [])
                fingerprint_components.append(",".join(sorted(fonts)))

            # Timezone (stable unless user changes it)
            if advanced_data.get("timezone"):
                fingerprint_components.append(advanced_data["timezone"].get("name", ""))
                fingerprint_components.append(
                    str(advanced_data["timezone"].get("offset", ""))
                )

            # Memory and CPU (stable)
            if advanced_data.get("memory"):
                fingerprint_components.append(
                    str(advanced_data["memory"].get("jsHeapSizeLimit", ""))
                )

        # Create hash from all components
        fingerprint_string = "|".join(str(c) for c in fingerprint_components)
        return hashlib.sha256(fingerprint_string.encode()).hexdigest()

    def check_device(
        self,
        fingerprint: str,
        current_name: str,
        ip_address: str,
        device_info: Dict,
        advanced_data: Optional[Dict] = None,
    ) -> Tuple[bool, Optional[Dict]]:
        """
        Check if a device has been seen before and record the visit

        Args:
            fingerprint: The device fingerprint
            current_name: Current identifier (e.g., Discord handle)
            ip_address: Current IP address
            device_info: Device information dict
            advanced_data: Optional advanced fingerprinting data

        Returns:
            Tuple of (is_returning_device, previous_visit_info)
        """
        current_time = datetime.now().isoformat()

        # Check if this fingerprint exists
        if fingerprint in self.device_history:
            device_record = self.device_history[fingerprint]
            previous_names = device_record.get("names", [])
            previous_ips = device_record.get("ip_addresses", [])
            visit_count = device_record.get("visit_count", 0)
            first_seen = device_record.get("first_seen")
            last_seen = device_record.get("last_seen")

            # Check if name has changed
            is_new_name = current_name not in previous_names

            # Update the record
            if current_name not in previous_names:
                previous_names.append(current_name)

            if ip_address not in previous_ips:
                previous_ips.append(ip_address)

            # Add to visit history
            visit_history = device_record.get("visit_history", [])
            visit_history.append(
                {
                    "timestamp": current_time,
                    "name": current_name,
                    "ip": ip_address,
                    "browser": f"{device_info.get('browser_family')} {device_info.get('browser_version')}",
                    "os": f"{device_info.get('os_family')} {device_info.get('os_version')}",
                }
            )

            # Update device record
            device_record["names"] = previous_names
            device_record["ip_addresses"] = previous_ips
            device_record["visit_count"] = visit_count + 1
            device_record["last_seen"] = current_time
            device_record["visit_history"] = visit_history[-20:]  # Keep last 20 visits
            device_record["last_device_info"] = self._sanitize_device_info(device_info)

            self.device_history[fingerprint] = device_record
            self._save_history()

            # Return recognition info
            return (
                True,
                {
                    "is_returning": True,
                    "is_new_name": is_new_name,
                    "previous_names": (
                        previous_names[:-1] if is_new_name else previous_names
                    ),
                    "current_name": current_name,
                    "previous_ips": previous_ips,
                    "visit_count": visit_count + 1,
                    "first_seen": first_seen,
                    "last_seen": last_seen,
                    "visit_history": visit_history[-5:],  # Last 5 visits for display
                    "fingerprint": fingerprint[:16] + "...",  # Truncated for display
                },
            )
        else:
            # New device - create record
            self.device_history[fingerprint] = {
                "fingerprint": fingerprint,
                "names": [current_name],
                "ip_addresses": [ip_address],
                "visit_count": 1,
                "first_seen": current_time,
                "last_seen": current_time,
                "visit_history": [
                    {
                        "timestamp": current_time,
                        "name": current_name,
                        "ip": ip_address,
                        "browser": f"{device_info.get('browser_family')} {device_info.get('browser_version')}",
                        "os": f"{device_info.get('os_family')} {device_info.get('os_version')}",
                    }
                ],
                "last_device_info": self._sanitize_device_info(device_info),
            }
            self._save_history()

            return (
                False,
                {
                    "is_returning": False,
                    "current_name": current_name,
                    "fingerprint": fingerprint[:16] + "...",
                },
            )

    def _sanitize_device_info(self, device_info: Dict) -> Dict:
        """Remove sensitive data from device_info before storage"""
        sanitized = {
            "browser_family": device_info.get("browser_family"),
            "browser_version": device_info.get("browser_version"),
            "os_family": device_info.get("os_family"),
            "os_version": device_info.get("os_version"),
            "is_mobile": device_info.get("is_mobile"),
            "is_tablet": device_info.get("is_tablet"),
            "is_pc": device_info.get("is_pc"),
        }
        return sanitized

    def get_statistics(self) -> Dict:
        """Get overall tracking statistics"""
        total_devices = len(self.device_history)
        total_visits = sum(
            record.get("visit_count", 0) for record in self.device_history.values()
        )
        returning_devices = sum(
            1
            for record in self.device_history.values()
            if record.get("visit_count", 0) > 1
        )
        devices_with_multiple_names = sum(
            1
            for record in self.device_history.values()
            if len(record.get("names", [])) > 1
        )

        return {
            "total_unique_devices": total_devices,
            "total_visits": total_visits,
            "returning_devices": returning_devices,
            "devices_with_multiple_names": devices_with_multiple_names,
            "new_devices": total_devices - returning_devices,
        }


# Global tracker instance
_tracker_instance = None


def get_tracker() -> DeviceTracker:
    """Get or create the global device tracker instance"""
    global _tracker_instance
    if _tracker_instance is None:
        _tracker_instance = DeviceTracker()
    return _tracker_instance
