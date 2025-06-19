"""
WeChat Safe Mode Encryption/Decryption Utility

This module provides a Python implementation of WeChat's Safe Mode encryption and decryption
protocol for secure message handling between WeChat servers and third-party applications.

Purpose:
--------
The WeChatSafeModeCrypto class implements the cryptographic protocol used by WeChat's
Safe Mode to ensure secure, authenticated communication between WeChat servers and
third-party applications.

How It Works:
-------------
1. ENCRYPTION PROCESS:
   - Generates a random 16-byte string for message uniqueness
   - Prepends message length (4 bytes, network byte order)
   - Appends the application ID (AppID) to the message
   - Applies PKCS#7 padding to make the total length a multiple of 32 bytes
   - Encrypts using AES-256-CBC with the provided encoding AES key
   - Base64 encodes the ciphertext
   - Generates SHA1 signature over token, timestamp, nonce, and encrypted data
   - Returns a response object with Encrypt, MsgSignature, TimeStamp, and Nonce

2. DECRYPTION PROCESS:
   - Validates the SHA1 signature to ensure message authenticity
   - Base64 decodes the ciphertext
   - Decrypts using AES-256-CBC with the same key and IV
   - Removes PKCS#7 padding
   - Extracts the original message and validates the AppID
   - Returns the plaintext message

Security Features:
-----------------
- AES-256-CBC encryption for message confidentiality
- SHA1 signature verification for message authenticity and integrity
- AppID validation to prevent message spoofing
- Random nonce generation for replay attack prevention
- Timestamp-based message freshness validation

Usage:
------
Initialize with your WeChat application credentials:
    crypto = WeChatSafeModeCrypto(token, encoding_aes_key, appid)

Encrypt outgoing messages:
    response = crypto.encrypt("Hello, WeChat!")

Decrypt incoming messages:
    plaintext = crypto.decrypt(encrypt_b64, msg_signature, timestamp, nonce)

Dependencies:
-------------
- pycryptodome: For AES encryption/decryption
- Standard library: base64, hashlib, struct, os, time

Author: Felipe Ramírez
Version: 1.0
License: MIT
"""

import base64
import hashlib
import struct
from Crypto.Cipher import AES
import os
import time

class WeChatSafeModeCrypto:
    def __init__(self, token: str, encoding_aes_key: str, appid: str):
        """
        Initialize the encryptor/decryptor with the shared token, AES key, and AppID.
        """
        self.token = token
        self.appid = appid
        # Append "=" and decode to get a 32-byte AES key
        self.aes_key = base64.b64decode(encoding_aes_key + "=")
        self.iv = self.aes_key[:16]  # IV is the first 16 bytes of AES key

    def _pkcs7_pad(self, data: bytes) -> bytes:
        """
        Apply PKCS#7 padding to make data length a multiple of 32 bytes.
        """
        pad_len = 32 - (len(data) % 32)
        return data + bytes([pad_len] * pad_len)

    def _pkcs7_unpad(self, data: bytes) -> bytes:
        """
        Remove PKCS#7 padding.
        """
        pad_len = data[-1]
        return data[:-pad_len]

    def _sha1_signature(self, token: str, timestamp: str, nonce: str, encrypt: str) -> str:
        """
        Compute SHA1 signature by lexicographically sorting and concatenating the fields.
        """
        parts = [token, timestamp, nonce, encrypt]
        parts.sort()
        return hashlib.sha1(''.join(parts).encode()).hexdigest()

    def encrypt(self, plaintext_msg: str) -> list[str, str]:
        """
        Encrypt the plaintext message according to WeChat Safe Mode format and return
        the response object containing Encrypt, MsgSignature, TimeStamp, and Nonce.
        """

        # Generate a random 16-byte string
        random_16b = os.urandom(16)

        # Generate a timestamp and nonce
        timestamp = str(int(time.time()))
        nonce = os.urandom(16).hex()
        
        # Encode message and get length in network byte order
        msg_bytes = plaintext_msg.encode()
        msg_len = struct.pack(">I", len(msg_bytes))

        # Construct the full payload: random(16B) + msg_len(4B) + msg + appid
        full_str = random_16b + msg_len + msg_bytes + self.appid.encode()

        # Pad the data to a multiple of 32 bytes using PKCS#7
        padded = self._pkcs7_pad(full_str)

        # AES encryption using CBC mode with IV
        cipher = AES.new(self.aes_key, AES.MODE_CBC, self.iv)
        encrypted = cipher.encrypt(padded)

        # Base64 encode the ciphertext
        encrypt_b64 = base64.b64encode(encrypted).decode()

        # Generate SHA1 signature over token, timestamp, nonce, encrypt
        signature = self._sha1_signature(self.token, timestamp, nonce, encrypt_b64)

        # Construct the final response object
        return {
            "Encrypt": encrypt_b64,
            "MsgSignature": signature,
            "TimeStamp": timestamp,
            "Nonce": nonce
        }

    def decrypt(self, encrypt_b64: str, msg_signature: str, timestamp: str, nonce: str) -> str:
        """
        Decrypt the base64-encoded ciphertext from a WeChat request and return the plaintext.
        Validates the signature and AppID.
        """
        # Verify SHA1 signature
        expected_signature = self._sha1_signature(self.token, timestamp, nonce, encrypt_b64)
        if expected_signature != msg_signature:
            raise ValueError("Invalid signature. Request may not be from WeChat.")

        # Base64 decode and decrypt the message
        cipher = AES.new(self.aes_key, AES.MODE_CBC, self.iv)
        decrypted_padded = cipher.decrypt(base64.b64decode(encrypt_b64))

        # Remove PKCS#7 padding
        decrypted = self._pkcs7_unpad(decrypted_padded)

        # Extract fields from decrypted payload
        random_16b = decrypted[:16]
        msg_len = struct.unpack(">I", decrypted[16:20])[0]
        msg = decrypted[20:20 + msg_len]
        appid = decrypted[20 + msg_len:].decode()

        # Validate AppID
        if appid != self.appid:
            raise ValueError("AppID mismatch. Possible spoofed request.")

        # Return plaintext message as string
        return msg.decode()
