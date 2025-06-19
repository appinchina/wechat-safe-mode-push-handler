import time
import hashlib
import random
import string
import json
import base64
import struct
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Configuration - replace with your actual values
WECHAT_TOKEN = "AAAAA"
WECHAT_ENCODING_AES_KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  # 43 characters
WECHAT_APPID = "wxba5fad812f8e6fb9"

def generate_nonce(length=16):
    """Generate a random nonce string."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def get_aes_key():
    """Get the AES key from the encoding AES key."""
    # WeChat uses a 43-character base64url-encoded key that should decode to 32 bytes
    # Convert base64url to standard base64
    key_modified = WECHAT_ENCODING_AES_KEY.replace('-', '+').replace('_', '/')
    
    # Add padding if needed (base64 requires length to be multiple of 4)
    padding_needed = len(key_modified) % 4
    if padding_needed:
        key_modified += '=' * (4 - padding_needed)
    
    try:
        decoded = base64.b64decode(key_modified)
        if len(decoded) != 32:
            raise ValueError(f"Invalid AES key length: {len(decoded)} bytes (expected 32)")
        return decoded
    except Exception as e:
        print(f"Failed to decode AES key: {str(e)}")
        print(f"Original key: {WECHAT_ENCODING_AES_KEY}")
        print(f"Modified key: {key_modified}")
        raise

def encrypt_message(msg: str) -> str:
    """Encrypt a message for testing."""
    try:
        aes_key = get_aes_key()
        print(f"AES key length: {len(aes_key)} bytes")  # Debug info
        
        random_bytes = os.urandom(16)
        msg_bytes = msg.encode('utf-8')
        msg_len = struct.pack('>I', len(msg_bytes))
        full_str = random_bytes + msg_len + msg_bytes + WECHAT_APPID.encode('utf-8')
        padded_data = pad(full_str, AES.block_size)
        iv = os.urandom(16)
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(padded_data)
        result = iv + encrypted
        return base64.b64encode(result).decode('utf-8')
    except Exception as e:
        print(f"Failed to encrypt message: {str(e)}")
        raise

def generate_msg_signature(token: str, timestamp: str, nonce: str, encrypt: str) -> str:
    """Generate msg_signature for encrypted messages."""
    params = [token, timestamp, nonce, encrypt]
    params.sort()
    param_str = ''.join(params)
    return hashlib.sha1(param_str.encode('utf-8')).hexdigest()

def generate_encrypted_test_commands():
    """Generate curl commands for testing encrypted WeChat endpoints."""
    # Generate parameters
    timestamp = str(int(time.time()))
    nonce = generate_nonce()
    
    # Sample message to encrypt
    sample_message = {
        "ToUserName": "gh_97417a04a28d",
        "FromUserName": "o9AgO5Kd5ggOC-bXrbNODIiE3bGY",
        "CreateTime": int(timestamp),
        "MsgType": "event",
        "Event": "debug_demo",
        "debug_str": "hello world"
    }
    
    # Encrypt the message
    msg_json = json.dumps(sample_message)
    encrypted_msg = encrypt_message(msg_json)
    
    # Generate msg_signature
    msg_signature = generate_msg_signature(WECHAT_TOKEN, timestamp, nonce, encrypted_msg)
    
    # Create the encrypted request body
    encrypted_body = {
        "ToUserName": "gh_97417a04a28d",
        "Encrypt": encrypted_msg
    }
    
    print("=== WeChat Encrypted Message Test Commands ===\n")
    
    # POST command for encrypted message receiving
    print("POST /wechat (encrypted message):")
    print(f'curl -X POST "http://localhost:8020/wechat?signature=test&timestamp={timestamp}&nonce={nonce}&msg_signature={msg_signature}&encrypt_type=aes" \\')
    print(f'  -H "Content-Type: application/json" \\')
    print(f'  -d \'{json.dumps(encrypted_body)}\'\n')
    
    print("=== Test Parameters ===")
    print(f"Token: {WECHAT_TOKEN}")
    print(f"EncodingAESKey: {WECHAT_ENCODING_AES_KEY}")
    print(f"AppID: {WECHAT_APPID}")
    print(f"Timestamp: {timestamp}")
    print(f"Nonce: {nonce}")
    print(f"MsgSignature: {msg_signature}")
    print(f"Encrypted Message: {encrypted_msg}")
    print(f"Original Message: {msg_json}")
    
    print("\n=== Configuration for app.py ===")
    print("Update these values in app.py:")
    print(f'WECHAT_TOKEN = "{WECHAT_TOKEN}"')
    print(f'WECHAT_ENCODING_AES_KEY = "{WECHAT_ENCODING_AES_KEY}"')
    print(f'WECHAT_APPID = "{WECHAT_APPID}"')

if __name__ == "__main__":
    generate_encrypted_test_commands() 