"""
GeoIP Redirect Service

This service redirects users based on their country of origin using GeoIP data. 
Users from Pakistan or India will be redirected to an alternative server, while users from other countries will be redirected to a default subdomain.

Dependencies:
- geoip2: A Python library for GeoIP2 databases.
- quart: An asynchronous web microframework for Python.

"""



import geoip2.database
from json_handler import *
from quart import Quart, redirect, request

app = Quart(__name__)
default_subdomain:str
alternative_server_url:str

# Load GeoIP database
reader = geoip2.database.Reader('GeoLite2-Country.mmdb')



@app.route('/')
async def index():
    """
    Index route handler to redirect users based on their country of origin.
    """
    global default_subdomain, alternative_server_url
    
    ip_address = request.remote_addr
    try:
        # Get country code from IP address
        response = reader.country(ip_address)
        country_code = response.country.iso_code

        # Check if IP address is in Pakistan or India
        if country_code in ['PK', 'IN']:
            return redirect(alternative_server_url)
    except Exception as e:
        print(f"Error: {e}")
    
    # Redirect to default subdomain for other countries
    default_url = f"{default_subdomain}{request.path}"
    return redirect(default_url)

if __name__ == '__main__':
    
    config = read_json_file('config.json')
    
    
    
    default_subdomain = config['default_server']

    alternative_server_url = config['honeypot_server']
    
    app_port = int(config['app_port'])
    
    app.run(port = app_port)