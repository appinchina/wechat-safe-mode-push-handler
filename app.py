from fastapi import FastAPI, Request, HTTPException, Response
import hashlib
import logging
import json
from typing import List

# Configure basic logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = FastAPI(title="WeChat Push Notification Receiver")

# Configuration - replace with your actual values
WECHAT_TOKEN = "YOUR_WECHAT_TOKEN_HERE"

def verify_signature(token: str, timestamp: str, nonce: str, signature: str) -> bool:
    """Verify the signature from WeChat server."""
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
async def receive_message(request: Request):
    """Handle WeChat push notifications."""
    logger.info(f"POST /wechat - Client: {request.client.host if request.client else 'unknown'}")
    
    # Get query parameters
    params = dict(request.query_params)
    signature = params.get("signature")
    timestamp = params.get("timestamp")
    nonce = params.get("nonce")
    
    # Verify signature
    if not verify_signature(WECHAT_TOKEN, timestamp, nonce, signature):
        logger.error("Signature verification failed")
        raise HTTPException(status_code=403, detail="Invalid signature")
    
    try:
        # Get message body
        body = await request.json()
        logger.info(f"Received message: {json.dumps(body, ensure_ascii=False)}")
        
        # Process the message based on its type
        msg_type = body.get("MsgType")
        from_user = body.get("FromUserName", "unknown")
        
        logger.info(f"Message type: {msg_type}, From: {from_user}")
        
        if msg_type == "event":
            event = body.get("Event")
            logger.info(f"Received event: {event}")
            # Handle events here
        
        elif msg_type == "text":
            content = body.get("Content", "")
            logger.info(f"Received text: {content}")
            # Handle text messages here
        
        else:
            logger.info(f"Received message of type: {msg_type}")
            # Handle other message types here
        
        return {"status": "success"}
        
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse JSON: {str(e)}")
        raise HTTPException(status_code=400, detail="Invalid JSON")
        
    except Exception as e:
        logger.error(f"Error processing message: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000) 