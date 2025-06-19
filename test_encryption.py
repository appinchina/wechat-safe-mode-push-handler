#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Test script to verify the updated encryption/decryption implementation

NOTE: This script uses test values for demonstration purposes.
For real testing, replace the test configuration with your actual WeChat credentials:
- WECHAT_TOKEN: Your WeChat token
- WECHAT_ENCODING_AES_KEY: Your 43-character encoding AES key
- WECHAT_APPID: Your WeChat AppID
"""

import sys
import json
import xml.etree.cElementTree as ET

from WXBizMsgCrypt import WXBizMsgCrypt
import ierror

def test_encryption_decryption():
    """Test the encryption and decryption functionality."""
    
    # Test configuration (replace with your actual values)
    WECHAT_TOKEN = "AR3JDYTDKR63HH43UFODH"
    WECHAT_ENCODING_AES_KEY = "wfUTFVqieA4aOs3MedlGyP7f19OEpSMmhyetgdy25Gt"  # 43 characters
    WECHAT_APPID = "wx9cbe6d5b1f6e4e8a"

    # Initialize the crypt instance
    wxcpt = WXBizMsgCrypt(WECHAT_TOKEN, WECHAT_ENCODING_AES_KEY, WECHAT_APPID)
    
    # Test message
    test_msg = """<xml>
<ToUserName><![CDATA[gh_7f083739789a]]></ToUserName>
<FromUserName><![CDATA[oia2TjjewbmiOUlr6X-1crbLOvLw]]></FromUserName>
<CreateTime>1407743423</CreateTime>
<MsgType><![CDATA[text]]></MsgType>
<Content><![CDATA[Hello World]]></Content>
<MsgId>6054768590064713728</MsgId>
</xml>"""
    
    nonce = "1320562132"
    timestamp = "1409735669"
    
    print("Testing encryption...")
    try:
        # Encrypt the message
        ret, encrypted_xml = wxcpt.EncryptMsg(test_msg, nonce, timestamp)
        
        if ret != ierror.WXBizMsgCrypt_OK:
            print(f"Encryption failed with error code: {ret}")
            return False
        
        print("✓ Encryption successful")
        print(f"Encrypted XML: {encrypted_xml}")
        
        # Parse the encrypted XML to get the encrypted content
        xml_tree = ET.fromstring(encrypted_xml)
        encrypt_elem = xml_tree.find("Encrypt")
        msg_signature_elem = xml_tree.find("MsgSignature")
        
        if encrypt_elem is None or msg_signature_elem is None:
            print("✗ Failed to extract encrypted content or signature")
            return False
        
        encrypted_content = encrypt_elem.text
        msg_signature = msg_signature_elem.text
        
        print(f"Encrypted content: {encrypted_content}")
        print(f"Message signature: {msg_signature}")
        
        print("\nTesting decryption...")
        
        # Decrypt the message
        ret, decrypted_xml = wxcpt.DecryptMsg(encrypted_xml, msg_signature, timestamp, nonce)
        
        if ret != ierror.WXBizMsgCrypt_OK:
            print(f"Decryption failed with error code: {ret}")
            return False
        
        print("✓ Decryption successful")
        print(f"Decrypted XML: {decrypted_xml}")
        
        # Verify the decrypted content matches the original
        if decrypted_xml.strip() == test_msg.strip():
            print("✓ Content verification successful")
            return True
        else:
            print("✗ Content verification failed")
            print(f"Expected: {test_msg}")
            print(f"Got: {decrypted_xml}")
            return False
            
    except Exception as e:
        print(f"✗ Test failed with exception: {str(e)}")
        return False

def test_signature_verification():
    """Test the signature verification functionality."""
    
    # Use the same test configuration as the first function
    token = "AR3JDYTDKR63HH43UFODH"
    encoding_aes_key = "wfUTFVqieA4aOs3MedlGyP7f19OEpSMmhyetgdy25Gt"  # 43 characters
    appid = "wx9cbe6d5b1f6e4e8a"
    
    wxcpt = WXBizMsgCrypt(token, encoding_aes_key, appid)
    
    # Test data
    test_msg = "Hello World"
    nonce = "1320562132"
    timestamp = "1409735669"
    
    print("\nTesting signature verification...")
    try:
        # Encrypt and get signature
        ret, encrypted_xml = wxcpt.EncryptMsg(test_msg, nonce, timestamp)
        
        if ret != ierror.WXBizMsgCrypt_OK:
            print(f"Encryption failed: {ret}")
            return False
        
        # Parse to get signature
        xml_tree = ET.fromstring(encrypted_xml)
        msg_signature_elem = xml_tree.find("MsgSignature")
        encrypt_elem = xml_tree.find("Encrypt")
        
        if msg_signature_elem is None or encrypt_elem is None:
            print("✗ Failed to extract signature or encrypted content")
            return False
        
        msg_signature = msg_signature_elem.text
        encrypt_content = encrypt_elem.text
        
        # Test with correct signature
        ret, decrypted = wxcpt.DecryptMsg(encrypted_xml, msg_signature, timestamp, nonce)
        if ret == ierror.WXBizMsgCrypt_OK:
            print("✓ Correct signature verification successful")
        else:
            print(f"✗ Correct signature verification failed: {ret}")
            return False
        
        # Test with incorrect signature
        wrong_signature = "wrong_signature_here"
        ret, decrypted = wxcpt.DecryptMsg(encrypted_xml, wrong_signature, timestamp, nonce)
        if ret == ierror.WXBizMsgCrypt_ValidateSignature_Error:
            print("✓ Incorrect signature properly rejected")
            return True
        else:
            print(f"✗ Incorrect signature not properly rejected: {ret}")
            return False
            
    except Exception as e:
        print(f"✗ Signature verification test failed: {str(e)}")
        return False

if __name__ == "__main__":
    print("WeChat Encryption/Decryption Test")
    print("=" * 40)
    
    # Note: These tests require valid WeChat configuration
    # print("Note: Update the configuration variables with your actual WeChat credentials to run the tests.")
    # print("Current configuration uses placeholder values.")
    # print("\nTest completed. Please update credentials and uncomment test calls to run actual tests.") 
    
    # Uncomment the following lines after setting up your credentials:
    test_encryption_decryption()
    test_signature_verification()
    