from fastapi import FastAPI, Request, HTTPException, Response
import hashlib
import logging
import json
import time
from typing import List, Dict, Any
import sys
import xml.etree.cElementTree as ET

# Add the Python directory to the path to import WXBizMsgCrypt
from WXBizMsgCrypt import WXBizMsgCrypt
import ierror

# Configure basic logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = FastAPI(title="WeChat Push Notification Receiver")

# Configuration - replace with your actual values
WECHAT_TOKEN = "AR3JDYTDKR63HH43UFODH"
WECHAT_ENCODING_AES_KEY = "wfUTFVqieA4aOs3MedlGyP7f19OEpSMmhyetgdy25Gt"  # 43 characters
WECHAT_APPID = "wx9cbe6d5b1f6e4e8a"

# Initialize the WeChat message crypt instance
wxcpt = WXBizMsgCrypt(WECHAT_TOKEN, WECHAT_ENCODING_AES_KEY, WECHAT_APPID)

def verify_msg_signature(token: str, timestamp: str, nonce: str, encrypt: str, msg_signature: str) -> bool:
    """Verify the msg_signature for encrypted messages."""
    params: List[str] = [token, timestamp, nonce, encrypt]
    params.sort()
    param_str = ''.join(params)
    hash_obj = hashlib.sha1(param_str.encode('utf-8'))
    calculated_signature = hash_obj.hexdigest()
    return calculated_signature == msg_signature

def verify_signature(token: str, timestamp: str, nonce: str, signature: str) -> bool:
    """Verify the signature from WeChat server (for non-encrypted messages)."""
    params: List[str] = [token, timestamp, nonce]
    params.sort()
    param_str = ''.join(params)
    hash_obj = hashlib.sha1(param_str.encode('utf-8'))
    calculated_signature = hash_obj.hexdigest()
    return calculated_signature == signature

def decrypt_message(encrypted_msg: str, msg_signature: str, timestamp: str, nonce: str) -> str:
    """Decrypt the encrypted message from WeChat using the official implementation."""
    try:
        # The WXBizMsgCrypt.DecryptMsg method expects XML format with Encrypt tag
        # We need to wrap the encrypted message in XML format
        xml_data = f'<xml><Encrypt><![CDATA[{encrypted_msg}]]></Encrypt></xml>'
        
        # Use the official decrypt method with proper signature parameters
        ret, decrypted_xml = wxcpt.DecryptMsg(xml_data, msg_signature, timestamp, nonce)
        
        if ret != ierror.WXBizMsgCrypt_OK:
            logger.error(f"Decryption failed with error code: {ret}")
            raise ValueError(f"Decryption failed with error code: {ret}")
        
        return decrypted_xml
        
    except Exception as e:
        logger.error(f"Failed to decrypt message: {str(e)}")
        raise

def encrypt_message(msg: str, timestamp: str, nonce: str) -> Dict[str, Any]:
    """Encrypt a message for response to WeChat using the official implementation."""
    try:
        # Use the official encrypt method
        ret, encrypted_xml = wxcpt.EncryptMsg(msg, nonce, timestamp)
        
        if ret != ierror.WXBizMsgCrypt_OK:
            logger.error(f"Encryption failed with error code: {ret}")
            raise ValueError(f"Encryption failed with error code: {ret}")
        
        # Parse the XML response to extract the components
        xml_tree = ET.fromstring(encrypted_xml)
        encrypt_elem = xml_tree.find("Encrypt")
        msg_signature_elem = xml_tree.find("MsgSignature")
        timestamp_elem = xml_tree.find("TimeStamp")
        nonce_elem = xml_tree.find("Nonce")
        
        return {
            "Encrypt": encrypt_elem.text if encrypt_elem is not None else "",
            "MsgSignature": msg_signature_elem.text if msg_signature_elem is not None else "",
            "TimeStamp": timestamp_elem.text if timestamp_elem is not None else timestamp,
            "Nonce": nonce_elem.text if nonce_elem is not None else nonce
        }
        
    except Exception as e:
        logger.error(f"Failed to encrypt message: {str(e)}")
        raise

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
async def receive_message(request: Request):
    """Handle WeChat push notifications with security mode."""
    logger.info(f"POST /wechat - Client: {request.client.host if request.client else 'unknown'}")
    
    # Get query parameters
    params = dict(request.query_params)
    signature = params.get("signature")
    timestamp = params.get("timestamp")
    nonce = params.get("nonce")
    msg_signature = params.get("msg_signature")
    encrypt_type = params.get("encrypt_type")
    
    try:
        # Get message body
        body = await request.json()
        logger.info(f"Received message: {json.dumps(body, ensure_ascii=False)}")
        
        # Check if this is an encrypted message
        if encrypt_type == "aes" and msg_signature:
            # Verify msg_signature for encrypted messages
            encrypt = body.get("Encrypt")
            if not encrypt:
                raise HTTPException(status_code=400, detail="Missing Encrypt field")
            
            if not verify_msg_signature(WECHAT_TOKEN, timestamp, nonce, encrypt, msg_signature):
                logger.error("Msg signature verification failed")
                raise HTTPException(status_code=403, detail="Invalid msg_signature")
            
            # Decrypt the message using official implementation
            decrypted_xml = decrypt_message(encrypt, msg_signature, timestamp, nonce)
            logger.info(f"Decrypted XML: {decrypted_xml}")
            
            # Parse the decrypted XML
            try:
                xml_tree = ET.fromstring(decrypted_xml)
                decrypted_body = {}
                for child in xml_tree:
                    decrypted_body[child.tag] = child.text
                
                logger.info(f"Decrypted message: {json.dumps(decrypted_body, ensure_ascii=False)}")
            except ET.ParseError as e:
                logger.error(f"Failed to parse decrypted XML: {str(e)}")
                raise HTTPException(status_code=400, detail="Invalid decrypted XML")
            
            # Process the decrypted message
            msg_type = decrypted_body.get("MsgType")
            from_user = decrypted_body.get("FromUserName", "unknown")
            
        else:
            # Handle non-encrypted messages (legacy mode)
            if not verify_signature(WECHAT_TOKEN, timestamp, nonce, signature):
                logger.error("Signature verification failed")
                raise HTTPException(status_code=403, detail="Invalid signature")
            
            decrypted_body = body
            msg_type = body.get("MsgType")
            from_user = body.get("FromUserName", "unknown")
        
        logger.info(f"Message type: {msg_type}, From: {from_user}")
        
        # Process the message based on its type
        response_msg = ""
        
        if msg_type == "event":
            event = decrypted_body.get("Event")
            logger.info(f"Received event: {event}")
            # Handle events here
            response_msg = '{"demo_resp":"event received"}'
        
        elif msg_type == "text":
            content = decrypted_body.get("Content", "")
            logger.info(f"Received text: {content}")
            # Handle text messages here
            response_msg = '{"demo_resp":"text received"}'
        
        else:
            logger.info(f"Received message of type: {msg_type}")
            # Handle other message types here
            response_msg = '{"demo_resp":"message received"}'
        
        # If this was an encrypted message, return encrypted response
        if encrypt_type == "aes" and msg_signature:
            encrypted_response = encrypt_message(response_msg, timestamp, nonce)
            logger.info(f"Sending encrypted response: {json.dumps(encrypted_response, ensure_ascii=False)}")
            return encrypted_response
        else:
            # Return plain response for non-encrypted messages
            return {"status": "success", "message": response_msg}
        
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse JSON: {str(e)}")
        raise HTTPException(status_code=400, detail="Invalid JSON")
        
    except Exception as e:
        logger.error(f"Error processing message: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8020) 