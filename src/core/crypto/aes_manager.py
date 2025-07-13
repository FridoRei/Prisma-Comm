from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
import base64

class AESManager:
    def __init__(self, key: bytes = None):
        if key:
            self.key = key
        else:
            self.key = get_random_bytes(32) 

    def get_key(self) -> bytes:
        return self.key

    def encrypt(self, plaintext: str) -> tuple[bytes, bytes, bytes]:
        cipher = AES.new(self.key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
        return cipher.nonce, ciphertext, tag

    def decrypt(self, nonce: bytes, ciphertext: bytes, tag: bytes) -> str:
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode('utf-8')

    @staticmethod
    def derive_key_from_password(password: str, salt: bytes = None) -> bytes:
        if salt is None:
            salt = get_random_bytes(16) 
        key = PBKDF2(password.encode('utf-8'), salt, dkLen=32, count=1000000, hmac_hash_module=SHA512)
        return key, salt

    @staticmethod
    def bytes_to_base64(data: bytes) -> str:
        return base64.b64encode(data).decode('utf-8')

    @staticmethod
    def base64_to_bytes(data_str: str) -> bytes:
        return base64.b64decode(data_str.encode('utf-8'))

