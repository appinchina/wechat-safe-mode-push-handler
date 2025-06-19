# WeChat Push Notification Handler

A FastAPI-based server for handling WeChat push notifications with comprehensive encryption support and JSON-based message processing.

## Overview

This application handles WeChat push notifications using a custom implementation of the WeChat encryption protocol. It supports both encrypted (security mode) and non-encrypted message formats, with comprehensive signature verification and message processing capabilities.

## Key Features

- **Custom WeChat Encryption**: Implements the official WeChat encryption protocol using `pycryptodome`
- **Security Mode Support**: Handles both encrypted and non-encrypted messages
- **Signature Verification**: Validates message authenticity using SHA1 signatures
- **FastAPI Framework**: Modern, fast web framework with automatic API documentation
- **Environment-based Configuration**: Secure credential management using `.env` files
- **JSON Message Processing**: Handles messages in JSON format for better integration
- **Comprehensive Logging**: Detailed logging for debugging and monitoring
- **Testing Utilities**: Built-in tools for generating test requests

## Installation

1. Clone the repository and navigate to the project directory:
```bash
git clone <repository-url>
cd wechat-notifications-handler
```

2. Create a virtual environment and activate it:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install the required dependencies:
```bash
pip install -r requirements.txt
```

4. Create a `.env` file in the project root with your WeChat credentials:
```bash
WECHAT_TOKEN=your_wechat_token_here
WECHAT_ENCODING_AES_KEY=your_encoding_aes_key_here
WECHAT_APPID=your_appid_here
```

## Configuration

### Environment Variables

The application uses environment variables for secure credential management:

- **WECHAT_TOKEN**: The token configured in your WeChat Official Account settings
- **WECHAT_ENCODING_AES_KEY**: The 43-character encoding AES key for encrypted messages
- **WECHAT_APPID**: Your WeChat Official Account AppID

### Security Modes

The application supports both security modes:
- **Plain Mode**: Messages are sent without encryption (legacy support)
- **Security Mode**: Messages are encrypted using AES-256-CBC with proper signature verification

## API Endpoints

### GET /wechat
WeChat server verification endpoint.

**Parameters:**
- `signature`: SHA1 signature
- `timestamp`: Timestamp
- `nonce`: Random string
- `echostr`: Echo string to return

**Response:** Returns the `echostr` if signature verification passes.

### POST /wechat
Receives WeChat push notifications.

**Query Parameters:**
- `signature`: SHA1 signature (for plain mode)
- `timestamp`: Timestamp
- `nonce`: Random string
- `msg_signature`: Message signature (for security mode)
- `encrypt_type`: Encryption type ("aes" for security mode)

**Request Body:** JSON message (encrypted or plain)

**Response:** JSON response (encrypted in security mode)

## Encryption Implementation

The application uses a custom implementation of the WeChat encryption protocol:

### Encryption Process
1. **Random String**: Add 16-byte random string for uniqueness
2. **Message Length**: Add 4-byte network byte order length
3. **AppID**: Append AppID at the end
4. **PKCS7 Padding**: Pad to 32-byte blocks
5. **AES-CBC Encryption**: Use key as both encryption key and IV
6. **Base64 Encoding**: Encode the result
7. **Signature Generation**: Create SHA1 signature over token, timestamp, nonce, and encrypted data

### Decryption Process
1. **Signature Verification**: Validate SHA1 signature
2. **Base64 Decoding**: Decode ciphertext
3. **AES-CBC Decryption**: Decrypt using key
4. **Remove Padding**: Remove PKCS7 padding
5. **Extract Components**: Parse message length, content, and AppID
6. **Validate AppID**: Ensure message comes from correct source

## Usage

### Running the Server

```bash
python app.py
```

The server will start on `http://127.0.0.1:8020`

### Testing

The project includes two testing utilities:

#### 1. Plain Text Mode Testing
```bash
python generate_curl_for_plain_text_mode.py
```
This generates curl commands for testing the endpoint in plain text mode.

#### 2. Security Mode Testing
```bash
python generate_curl_for_safe_mode.py
```
This generates encrypted test messages for testing the endpoint in security mode.

Both scripts will output ready-to-use curl commands that you can execute to test your endpoint.

## File Structure

```
├── app.py                              # Main FastAPI application
├── crypto_utils.py                     # Custom WeChat encryption implementation
├── generate_curl_for_plain_text_mode.py # Testing utility for plain text mode
├── generate_curl_for_safe_mode.py      # Testing utility for security mode
├── requirements.txt                    # Python dependencies
├── .env                                # Environment variables (create this)
├── .gitignore                          # Git ignore rules
└── README.md                           # This file
```

## Message Types Supported

The application handles various WeChat message types:

- **text**: Text messages from users
- **event**: System events (subscribe, unsubscribe, etc.)
- **Other types**: All other message types are logged and acknowledged

## Error Handling

The application includes comprehensive error handling:

- **Signature Verification**: Invalid signatures return 403 errors
- **JSON Parsing**: Invalid JSON returns 400 errors
- **Encryption Errors**: Decryption failures are logged and handled gracefully
- **General Errors**: All errors are logged with detailed information

## Security Considerations

1. **Environment Variables**: Never commit your `.env` file to version control
2. **HTTPS in Production**: Always use HTTPS in production environments
3. **Signature Validation**: All incoming requests are validated for authenticity
4. **AppID Verification**: Encrypted messages are validated against your AppID
5. **Comprehensive Logging**: Security events are logged for monitoring

## Development

### Adding New Message Types

To handle new message types, modify the message processing section in `app.py`:

```python
elif msg_type == "your_new_type":
    # Handle your new message type
    response_data = {
        "status": "success",
        "message": "your_new_type received",
        "timestamp": int(time.time())
    }
```

### Customizing Encryption

The encryption logic is contained in `crypto_utils.py`. The `WeChatSafeModeCrypto` class can be extended or modified as needed.

## Troubleshooting

### Common Issues

1. **Import Error for Crypto**: Ensure `pycryptodome` is installed (not `pycrypto`)
2. **Invalid AES Key**: Verify your EncodingAESKey is exactly 43 characters
3. **Signature Verification Failed**: Check that your Token matches WeChat settings
4. **AppID Mismatch**: Verify your AppID is correct in the `.env` file
5. **Environment Variables**: Ensure all required variables are set in `.env`

### Debug Mode

Enable debug logging by modifying the logging level in `app.py`:

```python
logging.basicConfig(level=logging.DEBUG)
```

## Dependencies

- **FastAPI**: Modern web framework for building APIs
- **uvicorn**: ASGI server for running the application
- **pycryptodome**: Cryptographic library for AES encryption
- **python-dotenv**: Environment variable management

## License

This project is open source and available under the MIT License.


