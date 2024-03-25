"""
GeoIP Redirect Service

This service redirects users based on their country of origin using GeoIP data. 
Users from Pakistan or India will be redirected to an alternative server, while users from other countries will be redirected to a default subdomain.

Dependencies:
- geoip2: A Python library for GeoIP2 databases.
- quart: An asynchronous web microframework for Python.

"""


from json_handler import *
from quart import Quart, redirect, request

app = Quart(__name__)
default_subdomain:str
alternative_server_url:str





@app.route('/')
async def index():
    """
    Index route handler to redirect users based on their country of origin.
    """
    global default_subdomain, alternative_server_url, reader
    
    ip_address = request.remote_addr
    try:
        # Get country code from IP address
        ip_address = request.remote_addr
        country_code = await get_country(ip_address)

        # Check if IP address is in Pakistan or India
        if country_code in ['PK', 'IN']:
            return redirect(alternative_server_url)
    except Exception as e:
        print(f"Error: {e}")
    
    # Redirect to default subdomain for other countries
    default_url = f"{default_subdomain}{request.path}"
    return redirect(default_url)

async def get_country(ip_address):
    """Retrieve country information for the given IP address."""
    try:
        response = await request_ip_location(ip_address)
        if response and response.get("response_code") == "200":
            country_code = response.get("country_code2")
            return country_code
    except Exception as e:
        print(f"Error fetching country information: {e}")
    return None

async def request_ip_location(ip_address):
    """Make a request to the IP location API."""
    url = f"https://api.iplocation.net/?cmd=ip-country&ip={ip_address}"
    try:
        response = await request.get(url)
        if response.status_code == 200:
            return response.json()
    except Exception as e:
        print(f"Error fetching IP location: {e}")
    return None


if __name__ == '__main__':
    
    config = read_json_file('config.json')
    
    
    
    default_subdomain = config['default_server']

    alternative_server_url = config['honeypot_server']
    
    app_port = int(config['app_port'])
  
    
    app.run(port = app_port)