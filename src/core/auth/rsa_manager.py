from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import os

PRIVATE_KEY_PATH = "private_key.pem"
PUBLIC_KEY_PATH = "public_key.pem"

class RSAManager:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._private_key = None
            cls._public_key = None
            cls._initialize_keys()
        return cls._instance

    @classmethod
    def _initialize_keys(cls):
        """Gera e carrega chaves RSA no Singleton"""
        if not os.path.exists(PRIVATE_KEY_PATH):
            cls._generate_keys()
        cls._private_key = cls._load_key_file(PRIVATE_KEY_PATH)
        cls._public_key = cls._load_key_file(PUBLIC_KEY_PATH)

    @classmethod
    def _generate_keys(cls):
        key = RSA.generate(2048)
        with open(PRIVATE_KEY_PATH, "wb") as f:
            f.write(key.export_key())
        with open(PUBLIC_KEY_PATH, "wb") as f:
            f.write(key.publickey().export_key())

    @classmethod
    def _load_key_file(cls, key_data):
        """Carrega uma chave RSA a partir de um caminho de arquivo ou de dados em bytes."""
        if isinstance(key_data, bytes):
            return RSA.import_key(key_data)
        elif isinstance(key_data, str) and os.path.exists(key_data):
            with open(key_data, "rb") as f:
                return RSA.import_key(f.read())
        else:
            raise ValueError("key_data deve ser um caminho de arquivo ou bytes da chave.")

    @classmethod
    def get_public_key(cls):
        return cls._public_key

    @classmethod
    def decrypt_token(cls, encrypted_token: bytes) -> str:
        """Descriptografa token diretamente usando a chave privada interna"""
        if not cls._private_key:
            raise ValueError("Chave privada RSA não carregada")
        
        cipher = PKCS1_OAEP.new(cls._private_key)
        return cipher.decrypt(encrypted_token).decode('utf-8')
    
    @classmethod
    def encrypt_with_public_key(cls, data: bytes, public_key) -> bytes:
        """Criptografa dados usando a chave pública."""
        if not public_key:
            raise ValueError("Chave pública não fornecida")
        
        cipher = PKCS1_OAEP.new(public_key)
        return cipher.encrypt(data)

# Exemplo de uso:
if __name__ == "__main__":
    # Teste de funcionalidade
    manager = RSAManager()
    pub_key = manager.get_public_key()
    
    message = b"TokenSecreto123"
    cipher = PKCS1_OAEP.new(pub_key)
    encrypted = cipher.encrypt(message)
    
    decrypted = manager.decrypt_token(encrypted)
    print(f"Original: {message.decode()}, Descriptografado: {decrypted}")
