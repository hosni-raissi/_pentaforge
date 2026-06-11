import requests
from bs4 import BeautifulSoup
import base64
import time
import urllib.parse

def get_csrf_token(url: str, name: str = "csrf_token", method: str = "GET", headers: dict = None) -> str:
    """
    Fetches a webpage, parses the HTML, and extracts the value of a hidden CSRF token input field.
    """
    try:
        session = requests.Session()
        res = session.request(method, url, headers=headers, timeout=10, verify=False)
        soup = BeautifulSoup(res.text, 'html.parser')
        
        # Look for standard hidden input fields
        token_input = soup.find('input', {'name': name})
        if token_input and 'value' in token_input.attrs:
            return token_input['value']
            
        # Fallback: look for meta tags commonly used in SPAs
        meta_token = soup.find('meta', {'name': name})
        if meta_token and 'content' in meta_token.attrs:
            return meta_token['content']
            
        raise ValueError(f"Could not find CSRF token with name '{name}' on page {url}")
    except Exception as e:
        raise Exception(f"Failed to fetch CSRF token: {str(e)}")

def custom_b64_request(url: str, payload: str, append_token: str = None, add_timestamp: bool = False, method: str = "POST") -> requests.Response:
    """
    Helper function for weird targets that require base64 encoded payloads mixed with CSRF tokens.
    """
    headers = {}
    if add_timestamp:
        headers['X-Timestamp'] = str(int(time.time()))
        
    if append_token:
        combined = f"{payload}|{append_token}"
    else:
        combined = payload
        
    encoded_payload = base64.b64encode(combined.encode()).decode('utf-8')
    
    data = {'p': encoded_payload}
    
    return requests.request(method, url, data=data, headers=headers, timeout=10, verify=False)

def encode_payload_for_waf(payload: str, encoding: str = "url") -> str:
    """
    Quickly encodes an injection payload to bypass basic WAFs.
    Options: 'url', 'double_url', 'hex'
    """
    if encoding == "url":
        return urllib.parse.quote(payload)
    elif encoding == "double_url":
        return urllib.parse.quote(urllib.parse.quote(payload))
    elif encoding == "hex":
        return "".join([hex(ord(c)).replace("0x", "%") for c in payload])
    return payload
