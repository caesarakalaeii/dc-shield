"""
GeoIP Redirect Service

This service redirects users based on their country of origin using GeoIP data. 
Users from Pakistan or India will be redirected to an alternative server, while users from other countries will be redirected to a default subdomain.

Dependencies:
- geoip2: A Python library for GeoIP2 databases.
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

@app.route('/')
async def index():
    ip_address = request.remote_addr
    country_code = await get_country(ip_address)
    l.info(f'Country code is: {country_code}')
    if country_code and country_code in ['PK', 'IN', 'DE']:
        return redirect(alternative_server_url)
    else:
        
        print(default_server)
        return redirect(default_server)
    



if __name__ == '__main__':
    
    config = read_json_file('config.json')
    
    
    
    default_server = config['default_server']

    alternative_server_url = config['honeypot_server']
    
    app_port = int(config['app_port'])
  
    
    app.run(port = app_port)