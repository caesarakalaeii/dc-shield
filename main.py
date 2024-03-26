"""
GeoIP Redirect Service

This service redirects users based on their country of origin using GeoIP data. 
Users from Pakistan or India will be redirected to an alternative server, while users from other countries will be redirected to a default subdomain.

Dependencies:
- quart: An asynchronous web microframework for Python.

"""

import requests
from logger import Logger
from json_handler import *
from quart import Quart, redirect, request

app = Quart(__name__)
l = Logger(console_log= True, file_logging=True, file_URI='logs/log.txt', override=True)
default_server:str
alternative_server_url:str
test_flag:bool
redirected:bool




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
        return redirect(honeypot)
    
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


if __name__ == '__main__':
    
    config = read_json_file('config.json')
    test_flag = True
    redirected = False
    
    default_server = config['default_server']

    alternative_server_url = config['honeypot_server']
    
    app_port = int(config['app_port'])
  
    
    app.run(host='0.0.0.0',port = app_port)