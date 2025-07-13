from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import os 

class RSAManager:  
    def __init__(self):
        self._private_key = None 
        self._public_key = None  

    def generate_temp_keys(self):
        key = RSA.generate(2048)
        self._private_key = key
        self._public_key = key.publickey()

    def clear_keys(self):
        self._private_key = None
        self._public_key = None

    def get_public_key(self):
        if not self._public_key:
            raise ValueError("Chave pública não gerada. Chame generate_ephemeral_keys() primeiro.")
        return self._public_key

    def get_public_key_bytes(self):
        if self._public_key:
            return self._public_key.export_key()
        return None

    def decrypt_bytes(self, encrypted_data: bytes) -> bytes:
        if not self._private_key:
            raise ValueError("Chave privada RSA não carregada. Chame generate_ephemeral_keys() primeiro.")
        
        cipher = PKCS1_OAEP.new(self._private_key)
        return cipher.decrypt(encrypted_data)

    def decrypt_string(self, encrypted_token: bytes) -> str:
        if not self._private_key:
            raise ValueError("Chave privada RSA não carregada. Chame generate_ephemeral_keys() primeiro.")
        
        cipher = PKCS1_OAEP.new(self._private_key)
        return cipher.decrypt(encrypted_token).decode('utf-8')
    
    @classmethod 
    def encrypt_with_public_key(cls, data: bytes, public_key) -> bytes:
        if not public_key:
            raise ValueError("Chave pública não fornecida")
        
        cipher = PKCS1_OAEP.new(public_key)
        return cipher.encrypt(data)

    @classmethod
    def _load_key_file(cls, key_data):
        if isinstance(key_data, bytes):
            return RSA.import_key(key_data)
        else:
            raise ValueError("key_data deve ser bytes da chave.")
