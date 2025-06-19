"""
WeChat Push Notification Receiver - Security Mode Handler

Purpose:
    This FastAPI application serves as a webhook endpoint for receiving and processing
    push notifications from WeChat Official Accounts. It supports both encrypted
    (security mode) and non-encrypted message formats, with comprehensive signature
    verification and message decryption capabilities.

Key Features:
    - WeChat server verification endpoint (GET /wechat)
    - Push notification receiver (POST /wechat)
    - Support for encrypted messages using AES encryption (security mode)
    - Support for non-encrypted messages (plain text mode)
    - Automatic signature verification for message authenticity
    - JSON-based message processing and response formatting
    - Comprehensive logging for debugging and monitoring

Configuration:
    The application requires the following environment variables (set in .env file):
    - WECHAT_TOKEN: The token configured in WeChat Official Account settings
    - WECHAT_ENCODING_AES_KEY: The encoding AES key for encrypted messages
    - WECHAT_APPID: The WeChat Official Account AppID

Message Flow:
    1. WeChat server sends verification request (GET) or push notification (POST)
    2. Application verifies signature to ensure message authenticity
    3. For encrypted messages: decrypts the message using AES encryption
    4. Parses the message content and determines message type
    5. Processes the message based on type (text, event, etc.)
    6. Returns appropriate response (encrypted or plain JSON)

Security Features:
    - SHA1 signature verification for all incoming requests
    - AES encryption/decryption for sensitive message content
    - Comprehensive error handling and logging
    - Input validation and sanitization

Message Types Supported:
    - text: Text messages from users
    - event: System events (subscribe, unsubscribe, etc.)
    - Other message types are logged and acknowledged

Usage:
    Run the application with: python app.py
    The server will start on http://127.0.0.1:8020
    Configure the webhook URL in WeChat Official Account settings to point to this endpoint

Dependencies:
    - FastAPI: Web framework for API endpoints
    - crypto_utils: Custom module for WeChat encryption/decryption
    - python-dotenv: Environment variable management
    - uvicorn: ASGI server for running the application
"""

from fastapi import FastAPI, Request, HTTPException, Response
import hashlib
import logging
import json
import time
from typing import List, Dict, Any
from crypto_utils import WeChatSafeModeCrypto
from dotenv import load_dotenv
import os

load_dotenv()

# Configure basic logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = FastAPI(title="WeChat Push Notification Receiver")

# Configuration - now loaded from .env
WECHAT_TOKEN = os.getenv("WECHAT_TOKEN")
WECHAT_ENCODING_AES_KEY = os.getenv("WECHAT_ENCODING_AES_KEY")
WECHAT_APPID = os.getenv("WECHAT_APPID")

crypto = WeChatSafeModeCrypto(WECHAT_TOKEN, WECHAT_ENCODING_AES_KEY, WECHAT_APPID)

def verify_signature(token: str, timestamp: str, nonce: str, signature: str) -> bool:
    """Verify the signature from WeChat server (for non-encrypted messages)."""
    params: List[str] = [token, timestamp, nonce]
    params.sort()
    param_str = ''.join(params)
    hash_obj = hashlib.sha1(param_str.encode('utf-8'))
    calculated_signature = hash_obj.hexdigest()
    return calculated_signature == signature

@app.get("/wechat")
async def verify_wechat(
    signature: str,
    timestamp: str,
    nonce: str,
    echostr: str,
    request: Request
):
    """Handle WeChat server verification request."""
    logger.info(f"GET /wechat - Client: {request.client.host if request.client else 'unknown'}")
    
    if verify_signature(WECHAT_TOKEN, timestamp, nonce, signature):
        logger.info("Signature verification successful")
        return Response(content=echostr, media_type="text/plain")
    else:
        logger.error("Signature verification failed")
        raise HTTPException(status_code=403, detail="Invalid signature")

@app.post("/wechat")
async def receive_message(
    signature: str,
    timestamp: str,
    nonce: str,
    msg_signature: str,
    encrypt_type: str,
    request: Request
):
    """Handle WeChat push notifications with security mode - JSON format."""
    logger.info(f"POST /wechat - Client: {request.client.host if request.client else 'unknown'}")

    # Also log the query parameters
    logger.info(f"Query parameters: {request.query_params}")
    
    try:
        # Get message body
        body = await request.json()
        logger.info(f"Received message: {json.dumps(body, ensure_ascii=False)}")
        
        # Check if this is an encrypted message
        if encrypt_type == "aes" and msg_signature:
            # Verify msg_signature for encrypted messages
            to_user_name = body.get("ToUserName")
            encrypt = body.get("Encrypt")
            if not encrypt:
                raise HTTPException(status_code=400, detail="Missing Encrypt field")
            
            decrypted_data_plaintext = crypto.decrypt(encrypt, msg_signature, timestamp, nonce)

            decrypted_data_json = json.loads(decrypted_data_plaintext)
            
            # logger.info(f"Decrypted JSON: {json.dumps(decrypted_data_json, ensure_ascii=False)}")
            
            # Process the decrypted message
            msg_type = decrypted_data_json.get("MsgType")
            from_user = decrypted_data_json.get("FromUserName", "unknown")
        else:
            # Handle non-encrypted messages (legacy mode)
            if not verify_signature(WECHAT_TOKEN, timestamp, nonce, signature):
                logger.error("Signature verification failed")
                raise HTTPException(status_code=403, detail="Invalid signature")
            
            decrypted_data_json = body
            msg_type = body.get("MsgType")
            from_user = body.get("FromUserName", "unknown")
        
        logger.info(f"Message type: {msg_type}, From: {from_user}")
        
        # Process the message based on its type
        response_data = {}
        
        if msg_type == "event":
            event = decrypted_data_json.get("Event")
            logger.info(f"Received event: {event}")
            # Handle events here
            response_data = {
                "status": "success",
                "message": "event received",
                "event_type": event,
                "timestamp": int(time.time())
            }
        
        elif msg_type == "text":
            content = decrypted_data_json.get("Content", "")
            logger.info(f"Received text: {content}")
            # Handle text messages here
            response_data = {
                "status": "success",
                "message": "text received",
                "content": content,
                "timestamp": int(time.time())
            }
        
        else:
            logger.info(f"Received message of type: {msg_type}")
            # Handle other message types here
            response_data = {
                "status": "success",
                "message": "message received",
                "msg_type": msg_type,
                "timestamp": int(time.time())
            }
        
        # If this was an encrypted message, return encrypted response
        if encrypt_type == "aes" and msg_signature:
            encription_result = crypto.encrypt(json.dumps(response_data))
            return encription_result
        else:
            # Return plain JSON response for non-encrypted messages
            return response_data
        
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse JSON: {str(e)}")
        raise HTTPException(status_code=400, detail="Invalid JSON")
        
    except Exception as e:
        logger.error(f"Error processing message: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8020) 