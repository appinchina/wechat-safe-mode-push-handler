"""
WeChat Endpoint Test Command Generator

This script generates curl commands for testing WeChat webhook endpoints in plain text mode.
It's designed to help developers test their WeChat integration without encryption/decryption.

Purpose:
- Generate valid WeChat signature parameters (timestamp, nonce, signature)
- Create curl commands for both GET (verification) and POST (message receiving) endpoints
- Provide ready-to-use test commands for WeChat webhook development

How it works:
1. Loads WeChat configuration from environment variables (.env file)
2. Generates a random nonce and current timestamp
3. Creates a WeChat signature using the token, timestamp, and nonce
4. Outputs two curl commands:
   - GET request for WeChat server verification
   - POST request with sample message data for testing message handling

Environment Variables Required:
- WECHAT_TOKEN: Your WeChat token for signature verification
- WECHAT_ENCODING_AES_KEY: Your WeChat encoding AES key (not used in plain text mode)
- WECHAT_APPID: Your WeChat app ID

Usage:
    python generate_curl_for_plain_text_mode.py

Output:
    Two curl commands that can be executed to test your WeChat webhook endpoint.
"""

import time
import hashlib
import random
import string
import json
from dotenv import load_dotenv
import os

load_dotenv()

# Configuration - now loaded from .env  
WECHAT_TOKEN = os.getenv("WECHAT_TOKEN")
WECHAT_ENCODING_AES_KEY = os.getenv("WECHAT_ENCODING_AES_KEY")
WECHAT_APPID = os.getenv("WECHAT_APPID")

base_url = "http://localhost:8020/wechat"


def generate_nonce(length=16):
    """Generate a random nonce string."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def generate_signature(token, timestamp, nonce):
    """Generate WeChat signature."""
    params = [token, timestamp, nonce]
    params.sort()
    string_to_sign = ''.join(params)
    return hashlib.sha1(string_to_sign.encode('utf-8')).hexdigest()

def generate_curl_commands():
    """Generate curl commands for testing WeChat endpoints."""
    # Generate parameters
    timestamp = str(int(time.time()))
    nonce = generate_nonce()
    signature = generate_signature(WECHAT_TOKEN, timestamp, nonce)
    echostr = "test_echo_string"
    
    # Sample message for POST request
    sample_message = {
        "ToUserName": "gh_123456789abc",
        "FromUserName": "o123456789",
        "CreateTime": timestamp,
        "MsgType": "text",
        "Content": "Hello World",
        "MsgId": "1234567890123456"
    }
    
    print("=== WeChat Endpoint Test Commands ===\n")
    
    # GET command for verification
    print("GET /wechat (verification):")
    print(f'curl -X GET "{base_url}?signature={signature}&timestamp={timestamp}&nonce={nonce}&echostr={echostr}"\n')
    
    # POST command for message receiving
    print("POST /wechat (message receiving):")
    print(f'curl -X POST "{base_url}?signature={signature}&timestamp={timestamp}&nonce={nonce}" \\')
    print(f'  -H "Content-Type: application/json" \\')
    print(f'  -d \'{json.dumps(sample_message)}\'\n')
    
if __name__ == "__main__":
    generate_curl_commands() 