import json
import os
from json import JSONDecodeError
from typing import Any, Dict


def read_json_file(file_path:str)-> FileNotFoundError | JSONDecodeError | dict[Any, Any]:
    """
    Read a JSON file and return its content as a Python dictionary.
    
    Args:
    - file_path (str): The path to the JSON file.
    
    Returns:
    - dict: The content of the JSON file as a dictionary.
    """
    try:
        with open(file_path, 'r') as json_file:
            json_content = json.load(json_file)
        return json_content
    except FileNotFoundError as e:
        print(f"Error: File '{file_path}' not found.")
        return e
    except json.JSONDecodeError as e:
        print(f"Error: File '{file_path}' is not a valid JSON file.")
        return e
    
def get_env_vars():
    config = {
        "default_server": os.getenv("DEFAULT_SERVER", "YOUR DEFAULT SERVER INVITE"),
        "honeypot_server": os.getenv("HONEYPOT_SERVER", "YOUR DEFAULT HONEYPOT INVITE"),
        "dc_logging": os.getenv("DC_LOGGING", "true").lower() in ("true", "1"),
        "dc_webhook_url": os.getenv("DC_WEBHOOK_URL", "YOUR DEFAULT DC WEBHOOK"),
        "app_port": os.getenv("APP_PORT", "8095"),
        "test_flag": os.getenv("TEST_FLAG", "false").lower() in ("true", "1")
    }
    return config
    
def write_to_json_file(data, file_path):
    """
    Write data to a JSON file.
    
    Args:
    - data (dict): The data to be written, should be a dictionary.
    - file_path (str): The path to the JSON file to write.
    
    Returns:
    - bool: True if writing is successful, False otherwise.
    """
    try:
        with open(file_path, 'w') as json_file:
            json.dump(data, json_file, indent=4)
        return True
    except Exception as e:
        print(f"Error occurred while writing to file '{file_path}': {e}")
        return False