"""
WeChat Safe Mode Message Generator

This script generates encrypted WeChat messages for testing the WeChat Notifications Handler
in safe/encrypted mode. It implements the WeChat encryption protocol to create properly
formatted requests that can be sent to the handler endpoint.

PURPOSE:
- Generate test messages for the WeChat Notifications Handler
- Demonstrate proper WeChat encryption implementation
- Create curl commands for manual testing of the handler

FUNCTIONALITY:
1. Encrypts messages using AES-CBC encryption with WeChat's encoding AES key
2. Implements PKCS#7 padding for proper block alignment
3. Generates cryptographic signatures for message verification
4. Creates properly formatted query parameters and JSON payload
5. Outputs a complete curl command ready for testing

ENCRYPTION PROCESS:
1. Generate 16-byte random string
2. Create FullStr = random(16B) + msg_len(4B) + msg + appid
3. Apply PKCS#7 padding to align with 32-byte blocks
4. Encrypt using AES-CBC with IV = first 16 bytes of aes_key
5. Base64 encode the encrypted result

SIGNATURE GENERATION:
- Creates SHA1 hash from sorted concatenation of: token, timestamp, nonce, encrypt_base64
- Generates both legacy signature (without encrypted content) and msg_signature (with encrypted content)

REQUIRED ENVIRONMENT VARIABLES:
- WECHAT_TOKEN: WeChat verification token
- WECHAT_ENCODING_AES_KEY: 43-character base64-encoded AES key
- WECHAT_APPID: WeChat application ID

USAGE:
Run this script to generate a curl command that can be used to test the WeChat handler:
    python generate_curl_for_safe_mode.py

The output curl command can be executed to send an encrypted test message to the handler.
"""

import base64
import hashlib
import os
import struct
import time
import json
from Crypto.Cipher import AES
from urllib.parse import urlencode
from dotenv import load_dotenv
load_dotenv()

# Configuration
token = os.getenv("WECHAT_TOKEN")
encoding_aes_key = os.getenv("WECHAT_ENCODING_AES_KEY")
appid = os.getenv("WECHAT_APPID")
url_base = "http://127.0.0.1:8020/wechat"

# Message to encrypt (example)
plain_msg = {
    "ToUserName": "gh_97417a04a28d",
    "FromUserName": "o9AgO5Kd5ggOC-bXrbNODIiE3bGY",
    "CreateTime": 1714112445,
    "MsgType": "event",
    "Event": "debug_demo",
    "debug_str": "hello world"
}
plain_msg_str = json.dumps(plain_msg, separators=(',', ':'))  # compact form

# 1. Generate AES Key
aes_key = base64.b64decode(encoding_aes_key + "=")

# 2. Create FullStr = random(16B) + msg_len(4B) + msg + appid
random_bytes = os.urandom(16)
msg_len = struct.pack(">I", len(plain_msg_str.encode()))
full_str = random_bytes + msg_len + plain_msg_str.encode() + appid.encode()

# 3. PKCS#7 padding
block_size = 32
pad_len = block_size - (len(full_str) % block_size)
padding = bytes([pad_len] * pad_len)
padded_msg = full_str + padding

# 4. AES-CBC Encrypt (IV = first 16 bytes of aes_key)
cipher = AES.new(aes_key, AES.MODE_CBC, aes_key[:16])
encrypted = cipher.encrypt(padded_msg)
encrypt_base64 = base64.b64encode(encrypted).decode()

# 5. Prepare signature
timestamp = str(int(time.time()))
nonce = str(os.urandom(4).hex())
signature_items = sorted([token, timestamp, nonce, encrypt_base64])
signature_str = ''.join(signature_items)
msg_signature = hashlib.sha1(signature_str.encode()).hexdigest()

# 6. Construct request components
query_params = {
    "signature": hashlib.sha1(''.join(sorted([token, timestamp, nonce])).encode()).hexdigest(),  # legacy
    "timestamp": timestamp,
    "nonce": nonce,
    "openid": "o9AgO5Kd5ggOC-bXrbNODIiE3bGY",
    "encrypt_type": "aes",
    "msg_signature": msg_signature
}

json_payload = {
    "ToUserName": plain_msg["ToUserName"],
    "Encrypt": encrypt_base64
}

# 7. Output final curl command
print("\nGenerated curl command:\n")
print(f"""curl -X POST "{url_base}?{urlencode(query_params)}" \\
  -H "Content-Type: application/json" \\
  -d '{json.dumps(json_payload)}'
""")
