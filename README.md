# WeChat Push Notifications Receiver - Minimal Version

A minimalistic implementation of a WeChat push notifications receiver using FastAPI.

## Features

- **GET /wechat**: Handles WeChat server verification requests
- **POST /wechat**: Receives and processes WeChat push notifications
- Signature verification for security
- Basic logging for debugging
- **generate_curl.py**: Script to generate test curl commands

## Setup

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Update the WeChat token in `app.py`:
```python
WECHAT_TOKEN = "YOUR_ACTUAL_WECHAT_TOKEN"
```

3. Run the application:
```bash
python app.py
```

The server will start on `http://127.0.0.1:8020`

## Testing

Generate test curl commands:
```bash
python generate_curl.py
```

This will output ready-to-use curl commands for testing both endpoints.

## Endpoints

### GET /wechat
WeChat server verification endpoint. Required parameters:
- `signature`: Request signature
- `timestamp`: Request timestamp  
- `nonce`: Random number
- `echostr`: Echo string to return

### POST /wechat
Receives push notifications from WeChat. Query parameters:
- `signature`: Request signature
- `timestamp`: Request timestamp
- `nonce`: Random number

Request body contains the message data in JSON format.

## Configuration

Replace `YOUR_WECHAT_TOKEN_HERE` in both `app.py` and `generate_curl.py` with your actual WeChat token.

## Usage

This minimal version shows the essential structure for implementing WeChat push notification endpoints. Add your specific business logic in the message handling sections marked with comments. 