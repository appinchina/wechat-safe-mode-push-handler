import time
import hashlib
import random
import string
import json

# Configuration - replace with your actual token
WECHAT_TOKEN = "YOUR_WECHAT_TOKEN_HERE"

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
    print(f'curl -X GET "http://localhost:8020/wechat?signature={signature}&timestamp={timestamp}&nonce={nonce}&echostr={echostr}"\n')
    
    # POST command for message receiving
    print("POST /wechat (message receiving):")
    print(f'curl -X POST "http://localhost:8020/wechat?signature={signature}&timestamp={timestamp}&nonce={nonce}" \\')
    print(f'  -H "Content-Type: application/json" \\')
    print(f'  -d \'{json.dumps(sample_message)}\'\n')
    
    print("Note: Replace WECHAT_TOKEN in this script with your actual token.")

if __name__ == "__main__":
    generate_curl_commands() 