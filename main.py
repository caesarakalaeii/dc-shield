"""
GeoIP Redirect Service

This service redirects users based on their country of origin using GeoIP data. 
Users from Pakistan or India will be redirected to an alternative server, while users from other countries will be redirected to a default subdomain.

Dependencies:
- geoip2: A Python library for GeoIP2 databases.
- quart: An asynchronous web microframework for Python.

"""



import os
import geoip2.database
import requests
from json_handler import *
from quart import Quart, redirect, request

app = Quart(__name__)
default_subdomain:str
alternative_server_url:str
reader:geoip2.database.Reader





@app.route('/')
async def index():
    """
    Index route handler to redirect users based on their country of origin.
    """
    global default_subdomain, alternative_server_url, reader
    
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

def download_geoip_database():
    """Download the GeoLite2 Country database file."""
    url = 'https://geolite.maxmind.com/download/geoip/database/GeoLite2-Country.mmdb.gz'
    try:
        response = requests.get(url)
        response.raise_for_status()
        with open('GeoLite2-Country.mmdb.gz', 'wb') as f:
            f.write(response.content)
        return True
    except Exception as e:
        print(f"Error downloading GeoLite2 database: {e}")
        return False

def load_geoip_database():
    """Load GeoLite2 Country database."""
    if not os.path.exists('GeoLite2-Country.mmdb'):
        print("Downloading GeoLite2 Country database...")
        if not download_geoip_database():
            print("Failed to download GeoLite2 Country database.")
            return None
        else:
            print("GeoLite2 Country database downloaded successfully.")
            os.system('gunzip GeoLite2-Country.mmdb.gz')
    return geoip2.database.Reader('GeoLite2-Country.mmdb')



if __name__ == '__main__':
    
    config = read_json_file('config.json')
    
    
    
    default_subdomain = config['default_server']

    alternative_server_url = config['honeypot_server']
    
    app_port = int(config['app_port'])
    
    # Load GeoIP database
    reader = load_geoip_database()
    if reader == None:
        print('Failed to load database, exiting')
        exit()
    
    app.run(port = app_port)