# 🔍 Device Tracking & Recognition System

## Overview

DC-Shield now includes advanced device tracking capabilities that demonstrate persistent user identification across multiple visits, even when users attempt to hide their identity by changing names or using different accounts.

## 🎯 Educational Purpose

This feature demonstrates:
- **Persistent Tracking**: How websites can track users across sessions without cookies
- **Browser Fingerprinting**: Creating unique device signatures from browser characteristics
- **Identity Correlation**: Linking multiple identities to the same physical device
- **Privacy Evasion Detection**: Identifying when users attempt to hide their identity

## 🔧 How It Works

### 1. Fingerprint Generation

The system creates a unique device fingerprint by combining:

#### Basic Device Information
- Browser family and version
- Operating System
- Hardware hints (RAM, CPU architecture, screen resolution)
- Language and timezone settings

#### Advanced Fingerprinting Data
- **Canvas Fingerprint**: GPU-based rendering signature
- **WebGL Fingerprint**: Graphics card vendor and renderer
- **Audio Fingerprint**: Hardware-based audio processing signature
- **Font Detection**: Installed system fonts
- **Screen Details**: Resolution, color depth, pixel ratio

### 2. Device Recognition

When a user visits:
1. System generates fingerprint from collected data
2. Compares fingerprint against stored device history
3. Detects if device has been seen before
4. Checks if user identifier (name) has changed
5. Records visit with timestamp, IP, and browser info

### 3. Data Storage

Device information is stored in `device_history.json` with:
- Unique device fingerprint (SHA256 hash)
- List of all names/identities used
- IP address history
- Visit count and timestamps
- Visit history (last 20 visits)

## 📊 What Gets Displayed

### For New Devices
```
🆕 FIRST VISIT
✨ NEW DEVICE DETECTED

User Identity: `username`
Device Fingerprint: `a3f9d2c1e8b5...`

*This device will now be tracked across future visits*
```

### For Returning Devices (Same Name)
```
🔄 RETURNING VISITOR DETECTED
🔄 RETURNING DEVICE RECOGNIZED

User Identity: `username`

Visit Statistics:
└ Total visits: 3
└ First seen: 2025-10-16 14:23
└ Last seen: 2025-10-16 18:45

IP Address History:
└ `192.168.1.100`
└ `10.0.0.50`

Device Fingerprint: `a3f9d2c1e8b5...`
```

### For Returning Devices (Different Name) ⚠️
```
🔍 DEVICE RECOGNITION ANALYSIS
🚨 RETURNING DEVICE WITH NEW IDENTITY DETECTED

Current Identity: `new_username`
Previously Seen As:
└ `old_username`
└ `another_name`

Visit Statistics:
└ Total visits: 5
└ First seen: 2025-10-15 10:12
└ Last seen: 2025-10-16 19:30

IP Address History:
└ `192.168.1.100`
└ `10.0.0.50`
└ `172.16.0.20`

Device Fingerprint: `a3f9d2c1e8b5...`

📚 Educational Note: This demonstrates persistent tracking across sessions
using browser fingerprinting, even when users attempt to hide their identity.
```

## 🛡️ Technical Implementation

### File Structure
```
/device_tracker.py          - Core tracking logic
/main.py                    - Integration with web endpoints
/surveillance_embeds.py     - Discord embed display
/device_history.json        - Persistent storage (created at runtime)
```

### Key Functions

#### `DeviceTracker.generate_fingerprint(device_info, advanced_data)`
Creates SHA256 hash from device characteristics

#### `DeviceTracker.check_device(fingerprint, current_name, ip_address, device_info, advanced_data)`
Checks if device has been seen before and returns recognition info

#### `get_tracker()`
Returns singleton instance of the device tracker

### Integration Points

1. **Data Collection** (`/api/collect-advanced-data`)
   - Extracts device info from HTTP headers
   - Gets IP address from request
   - Retrieves user identifier from POST data
   - Calls device tracker

2. **Discord Notifications** (`send_advanced_data_to_discord`)
   - Generates fingerprint
   - Checks for previous visits
   - Includes recognition info in embed

3. **Web Interface** (`result.html`)
   - JavaScript extracts username from page
   - Sends user identifier with collected data

## 🎓 Educational Insights

### What This Demonstrates

1. **Cookie-less Tracking**: Tracking works even if users clear cookies
2. **Account Correlation**: Multiple accounts can be linked to one device
3. **Anonymity Failure**: Changing usernames doesn't hide your identity
4. **Fingerprint Persistence**: Hardware-based fingerprints are very stable
5. **Privacy Illusion**: Many users think clearing cookies = privacy

### Defense Strategies

To avoid device fingerprinting:

#### Level 1: Basic Protection
- Use Tor Browser (best option)
- Firefox with `privacy.resistFingerprinting = true`
- Use VPN to hide IP changes

#### Level 2: Advanced Protection
- Disable JavaScript (NoScript)
- Block Canvas/WebGL (Canvas Blocker extension)
- Disable WebRTC
- Use virtual machines

#### Level 3: Maximum Protection
- Whonix or Tails OS
- Hardware isolation
- Regular OS reinstalls
- Never reuse accounts

### Why This Matters

- **Ad Tracking**: Companies track users across sites
- **Social Engineering**: Attackers can link accounts to individuals
- **De-anonymization**: Anonymous accounts can be identified
- **Surveillance**: Governments use these techniques
- **Data Brokers**: Your profile is sold and shared

## 📈 Statistics Available

The tracker provides aggregate statistics:

```python
tracker.get_statistics()
# Returns:
{
    "total_unique_devices": 42,
    "total_visits": 128,
    "returning_devices": 18,
    "devices_with_multiple_names": 7,
    "new_devices": 24
}
```

## ⚠️ Privacy & Ethics

### Responsible Use
- **Educational Only**: For cybersecurity training
- **Obtain Consent**: Get permission before tracking
- **Secure Storage**: Protect device_history.json
- **Data Minimization**: Only collect what's needed
- **Transparent**: Inform users about tracking

### Legal Considerations
- Comply with GDPR, CCPA, and local laws
- Provide opt-out mechanisms
- Delete data upon request
- Don't use for malicious purposes

## 🔄 Data Management

### View Stored Data
```bash
cat device_history.json | python -m json.tool
```

### Delete All Tracking Data
```bash
rm device_history.json
```

### Delete Specific Device
Edit `device_history.json` and remove the device entry

## 🧪 Testing

To test the device tracking:

1. Visit `/ticket/user1` - Should show "NEW DEVICE DETECTED"
2. Visit `/ticket/user1` again - Should show "RETURNING VISITOR"
3. Visit `/ticket/user2` - Should show "RETURNING DEVICE WITH NEW IDENTITY"
4. Check Discord - Each visit should show recognition info
5. Check `device_history.json` - Should show visit history

## 📚 Further Reading

- [EFF: Browser Fingerprinting](https://coveryourtracks.eff.org/)
- [AmIUnique: Test Your Fingerprint](https://amiunique.org/)
- [FingerprintJS Research](https://fingerprintjs.com/blog/)
- [Academic Paper: The Web Never Forgets](https://securehomes.esat.kuleuven.be/~gacar/persistent/)

---

**Version**: 1.0
**Last Updated**: 2025-10-16
**For Educational Purposes Only**
