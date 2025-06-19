#!/usr/bin/env python
#-*- encoding:utf-8 -*-

""" Sample code for encrypting and decrypting messages sent by the public platform to public accounts.
@copyright: Copyright (c) 1998-2014 Tencent Inc.

"""
# ------------------------------------------------------------------------

import base64
import string
import random
import hashlib
import time
import struct
from Crypto.Cipher import AES
import xml.etree.cElementTree as ET
import sys
import socket
import ierror

"""
Regarding the Crypto.Cipher module, ImportError: No module named 'Crypto' solution
Please go to the official website https://www.dlitz.net/software/pycrypto/ to download pycrypto.
After downloading, follow the instructions in the "Installation" section of the README to install pycrypto.
"""
class FormatException(Exception):
    pass

def throw_exception(message, exception_class=FormatException):
    """my define raise exception function"""
    raise exception_class(message)

class SHA1:
    """Interface for calculating message signatures for the public platform"""

    def getSHA1(self, token, timestamp, nonce, encrypt):
        """Generate security signature using SHA1 algorithm
        @param token:  ticket
        @param timestamp: timestamp
        @param encrypt: ciphertext
        @param nonce: random string
        @return: security signature
        """
        try:
            sortlist = [token, timestamp, nonce, encrypt]
            sortlist.sort()
            sha = hashlib.sha1()
            sha.update("".join(sortlist).encode('utf-8'))
            return  ierror.WXBizMsgCrypt_OK, sha.hexdigest()
        except Exception as e:
            #print e
            return  ierror.WXBizMsgCrypt_ComputeSignature_Error, None


class XMLParse:
    """Interface for extracting ciphertext from message format and generating reply message format"""

    # xml message template
    AES_TEXT_RESPONSE_TEMPLATE = """<xml>
<Encrypt><![CDATA[%(msg_encrypt)s]]></Encrypt>
<MsgSignature><![CDATA[%(msg_signaturet)s]]></MsgSignature>
<TimeStamp>%(timestamp)s</TimeStamp>
<Nonce><![CDATA[%(nonce)s]]></Nonce>
</xml>"""

    def extract(self, xmltext):
        """Extract encrypted message from xml data packet
        @param xmltext: xml string to be extracted
        @return: extracted encrypted message string
        """
        try:
            xml_tree = ET.fromstring(xmltext)
            encrypt = xml_tree.find("Encrypt")
            if encrypt is None:
                return ierror.WXBizMsgCrypt_ParseXml_Error, None, None
            return ierror.WXBizMsgCrypt_OK, encrypt.text, None
        except Exception as e:
            #print e
            return ierror.WXBizMsgCrypt_ParseXml_Error, None, None

    def generate(self, encrypt, signature, timestamp, nonce):
        """Generate xml message
        @param encrypt: encrypted message ciphertext
        @param signature: security signature
        @param timestamp: timestamp
        @param nonce: random string
        @return: generated xml string
        """
        resp_dict = {
                    'msg_encrypt' : encrypt,
                    'msg_signaturet': signature,
                    'timestamp'    : timestamp,
                    'nonce'        : nonce,
                     }
        resp_xml = self.AES_TEXT_RESPONSE_TEMPLATE % resp_dict
        return resp_xml


class PKCS7Encoder():
    """Provides encryption and decryption interface based on PKCS7 algorithm"""

    block_size = 32
    def encode(self, data):
        """ Pad the data that needs to be encrypted
        @param data: data that needs padding operation (bytes)
        @return: padded data (bytes)
        """
        data_length = len(data)
        # Calculate the number of bits that need to be padded
        amount_to_pad = self.block_size - (data_length % self.block_size)
        if amount_to_pad == 0:
            amount_to_pad = self.block_size
        # Get the byte used for padding
        pad = bytes([amount_to_pad])
        return data + pad * amount_to_pad

    def decode(self, decrypted):
        """Remove padding characters from decrypted data
        @param decrypted: decrypted data (bytes)
        @return: data after removing padding characters (bytes)
        """
        pad = decrypted[-1]
        if pad < 1 or pad > 32:
            pad = 0
        return decrypted[:-pad]


class Prpcrypt(object):
    """Provides encryption and decryption interface for receiving and pushing messages to the public platform"""

    def __init__(self,key):
        #self.key = base64.b64decode(key+"=")
        self.key = key
        # Set encryption/decryption mode to AES CBC mode
        self.mode = AES.MODE_CBC


    def encrypt(self,text,appid):
        """Encrypt plaintext
        @param text: plaintext to be encrypted
        @return: encrypted string
        """
        # Add 16-bit random string to the beginning of plaintext
        random_str = self.get_random_str()
        msg_len = struct.pack("I", socket.htonl(len(text)))
        text_bytes = text.encode('utf-8')
        appid_bytes = appid.encode('utf-8')
        
        # Concatenate all components as bytes
        full_data = random_str.encode('utf-8') + msg_len + text_bytes + appid_bytes
        
        # Use custom padding method to pad plaintext
        pkcs7 = PKCS7Encoder()
        padded_data = pkcs7.encode(full_data)
        
        # Encrypt
        cryptor = AES.new(self.key, self.mode, self.key[:16])
        try:
            ciphertext = cryptor.encrypt(padded_data)
            # Use BASE64 to encode the encrypted string
            return ierror.WXBizMsgCrypt_OK, base64.b64encode(ciphertext).decode('utf-8')
        except Exception as e:
            #print e
            return ierror.WXBizMsgCrypt_EncryptAES_Error, None

    def decrypt(self,text,appid):
        """Remove padding from decrypted plaintext
        @param text: ciphertext
        @return: plaintext after removing padding
        """
        try:
            cryptor = AES.new(self.key, self.mode, self.key[:16])
            # Use BASE64 to decode ciphertext, then AES-CBC decrypt
            plain_text = cryptor.decrypt(base64.b64decode(text))
        except Exception as e:
            #print e
            return ierror.WXBizMsgCrypt_DecryptAES_Error, None
        try:
            pad = plain_text[-1]
            # Remove padding string
            # Remove 16-bit random string
            content = plain_text[16:-pad]
            xml_len = socket.ntohl(struct.unpack("I", content[:4])[0])
            xml_content = content[4:xml_len+4]
            from_appid = content[xml_len+4:]
            
            # Decode bytes to string
            xml_content_str = xml_content.decode('utf-8')
            from_appid_str = from_appid.decode('utf-8')
            
        except Exception as e:
            #print e
            return ierror.WXBizMsgCrypt_IllegalBuffer, None
        if from_appid_str != appid:
            return ierror.WXBizMsgCrypt_ValidateAppid_Error, None
        return 0, xml_content_str

    def get_random_str(self):
        """ Randomly generate 16-bit string
        @return: 16-bit string
        """
        rule = string.ascii_letters + string.digits
        str = random.sample(rule, 16)
        return "".join(str)

class WXBizMsgCrypt(object):
    # Constructor
    # @param sToken: Token set by developers on the public platform
    # @param sEncodingAESKey: EncodingAESKey set by developers on the public platform
    # @param sAppId: AppId of the enterprise account
    def __init__(self,sToken,sEncodingAESKey,sAppId):
        try:
            # Handle the 43-character key properly
            key_with_padding = sEncodingAESKey + "="
            self.key = base64.b64decode(key_with_padding)
            if len(self.key) != 32:
                # Try without padding
                self.key = base64.b64decode(sEncodingAESKey)
                if len(self.key) != 32:
                    throw_exception("[error]: EncodingAESKey invalid length!", FormatException)
        except Exception as e:
            throw_exception(f"[error]: EncodingAESKey invalid! {str(e)}", FormatException)
        self.token = sToken
        self.appid = sAppId

    def EncryptMsg(self, sReplyMsg, sNonce, timestamp = None):
        # Encrypt and package the reply message from the public account to the user
        #@param sReplyMsg: message to be replied to the user by the enterprise account, xml format string
        #@param sTimeStamp: timestamp, can be generated by yourself, or use the timestamp from URL parameters, if None then automatically use current time
        #@param sNonce: random string, can be generated by yourself, or use the nonce from URL parameters
        #sEncryptMsg: encrypted ciphertext that can be directly replied to the user, including xml format string with msg_signature, timestamp, nonce, encrypt
        #return: success 0, sEncryptMsg, failure returns corresponding error code None
        pc = Prpcrypt(self.key)
        ret,encrypt = pc.encrypt(sReplyMsg, self.appid)
        if ret != 0:
            return ret,None
        if timestamp is None:
            timestamp = str(int(time.time()))
        # Generate security signature
        sha1 = SHA1()
        ret,signature = sha1.getSHA1(self.token, timestamp, sNonce, encrypt)
        if ret != 0:
            return ret,None
        xmlParse = XMLParse()
        return ret,xmlParse.generate(encrypt, signature, timestamp, sNonce)

    def DecryptMsg(self, sPostData, sMsgSignature, sTimeStamp, sNonce):
        # Verify the authenticity of the message and get the decrypted plaintext
        # @param sMsgSignature: signature string, corresponding to the msg_signature parameter in the URL
        # @param sTimeStamp: timestamp, corresponding to the timestamp parameter in the URL
        # @param sNonce: random string, corresponding to the nonce parameter in the URL
        # @param sPostData: ciphertext, corresponding to the data in the POST request
        #  xml_content: decrypted original text, valid when return is 0
        # @return: success 0, failure returns corresponding error code
         # Verify security signature
        xmlParse = XMLParse()
        ret, encrypt, _ = xmlParse.extract(sPostData)
        if ret != 0:
            return ret, None
        sha1 = SHA1()
        ret, signature = sha1.getSHA1(self.token, sTimeStamp, sNonce, encrypt)
        if ret != 0:
            return ret, None
        if not signature == sMsgSignature:
            return ierror.WXBizMsgCrypt_ValidateSignature_Error, None
        pc = Prpcrypt(self.key)
        ret, xml_content = pc.decrypt(encrypt, self.appid)
        return ret, xml_content

