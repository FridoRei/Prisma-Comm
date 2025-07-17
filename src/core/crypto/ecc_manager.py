from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import os
import base64

class ECCManager:
    def __init__(self):
        self._x25519_private_key = None
        self._x25519_public_key = None
        self._ed25519_private_key = None
        self._ed25519_public_key = None

    def generate_x25519_keys(self):
        """Gera um novo par de chaves X25519 para a sessão."""
        self._x25519_private_key = x25519.X25519PrivateKey.generate()
        self._x25519_public_key = self._x25519_private_key.public_key()

    def get_x25519_public_key_bytes(self) -> bytes:
        """Retorna a chave pública X25519 em formato bytes."""
        if not self._x25519_public_key:
            print("[ERROR] [ECCManager] Tentativa de obter chave pública X25519 antes de ser gerada.")
            raise ValueError("Chave pública X25519 não gerada.")
        return self._x25519_public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    def derive_shared_key(self, peer_x25519_public_bytes: bytes, salt: bytes = None, info: bytes = None) -> bytes:
        """
        Deriva uma chave simétrica compartilhada usando ECDH (X25519) e HKDF.
        Args:
            peer_x25519_public_bytes: Chave pública X25519 do par em bytes.
            salt: Salt opcional para HKDF.
            info: Contexto opcional para HKDF.
        Returns:
            A chave simétrica derivada (32 bytes para AES-256).
        """
        if not self._x25519_private_key:
            print("[ERROR] [ECCManager] Tentativa de derivar chave compartilhada sem chave privada X25519 gerada.")
            raise ValueError("Chave privada X25519 não carregada/gerada.")
        
        try:
            peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_x25519_public_bytes)
            shared_key = self._x25519_private_key.exchange(peer_public_key)

            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,  
                salt=salt if salt else b"wifi-chat-salt",
                info=info if info else b"aes-gcm-key-derivation",
                backend=default_backend()
            )
            derived_key = hkdf.derive(shared_key)
            return derived_key
        except Exception as e:
            print(f"[ERROR] [ECCManager] Erro ao derivar chave compartilhada: {e}")
            raise

    def generate_ed25519_keys(self):
        """Gera um novo par de chaves Ed25519."""
        self._ed25519_private_key = ed25519.Ed25519PrivateKey.generate()
        self._ed25519_public_key = self._ed25519_private_key.public_key()

    def load_ed25519_private_key(self, key_bytes: bytes, password: bytes = None):
        """Carrega uma chave privada Ed25519 de bytes."""
        try:
            self._ed25519_private_key = serialization.load_pem_private_key(
                key_bytes,
                password=password,
                backend=default_backend()
            )
            self._ed25519_public_key = self._ed25519_private_key.public_key()
        except Exception as e:
            print(f"[ERROR] [ECCManager] Erro ao carregar chave privada Ed25519: {e}")
            raise

    def load_ed25519_public_key(self, key_bytes: bytes):
        """Carrega uma chave pública Ed25519 de bytes."""
        try:
            self._ed25519_public_key = serialization.load_pem_public_key(
                key_bytes,
                backend=default_backend()
            )
        except Exception as e:
            print(f"[ERROR] [ECCManager] Erro ao carregar chave pública Ed25519: {e}")
            raise

    def get_ed25519_public_key_pem(self) -> bytes:
        """Retorna a chave pública Ed25519 em formato PEM."""
        if not self._ed25519_public_key:
            print("[ERROR] [ECCManager] Tentativa de obter chave pública Ed25519 antes de ser carregada/gerada.")
            raise ValueError("Chave pública Ed25519 não carregada/gerada.")
        return self._ed25519_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def get_ed25519_private_key_pem(self, password: bytes = None) -> bytes:
        """Retorna a chave privada Ed25519 em formato PEM."""
        if not self._ed25519_private_key:
            print("[ERROR] [ECCManager] Tentativa de obter chave privada Ed25519 antes de ser carregada/gerada.")
            raise ValueError("Chave privada Ed25519 não carregada/gerada.")
        return self._ed25519_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption() if password is None else serialization.BestAvailableEncryption(password)
        )

    def sign_data(self, data: bytes) -> bytes:
        """Assina dados usando a chave privada Ed25519."""
        if not self._ed25519_private_key:
            print("[ERROR] [ECCManager] Tentativa de assinar dados sem chave privada Ed25519 carregada.")
            raise ValueError("Chave privada Ed25519 não carregada.")
        try:
            signature = self._ed25519_private_key.sign(data)
            return signature
        except Exception as e:
            print(f"[ERROR] [ECCManager] Erro ao assinar dados: {e}")
            raise

    @staticmethod
    def verify_signature(public_key_bytes: bytes, data: bytes, signature: bytes) -> bool:
        """Verifica uma assinatura usando uma chave pública Ed25519."""
        try:
            public_key = serialization.load_pem_public_key(
                public_key_bytes,
                backend=default_backend()
            )
            public_key.verify(signature, data)
            return True
        except Exception as e:
            print(f"[ERROR] [ECCManager] Falha na verificação da assinatura: {e}")
            return False

    def clear_x25519_keys(self):
        """Limpa as chaves X25519 da sessão."""
        self._x25519_private_key = None
        self._x25519_public_key = None

    def clear_ed25519_keys(self):
        """Limpa as chaves Ed25519 carregadas."""
        self._ed25519_private_key = None
        self._ed25519_public_key = None

    def has_ed25519_private_key(self) -> bool:
        return self._ed25519_private_key is not None

    def has_ed25519_public_key(self) -> bool:
        return self._ed25519_public_key is not None

    @staticmethod
    def bytes_to_base64(data: bytes) -> str:
        return base64.b64encode(data).decode('utf-8')

    @staticmethod
    def base64_to_bytes(data_str: str) -> bytes:
        return base64.b64decode(data_str.encode('utf-8'))

