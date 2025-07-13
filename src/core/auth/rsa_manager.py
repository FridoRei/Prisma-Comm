# src/core/auth/rsa_manager.py
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import os # Manter para compatibilidade, mas não será usado para arquivos

class RSAManager:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._private_key = None # Chave privada do servidor
            cls._public_key = None  # Chave pública do servidor
            # Não chamamos _initialize_keys() aqui, pois as chaves serão geradas sob demanda
        return cls._instance

    # Removemos _initialize_keys, _generate_keys e _load_key_file
    # pois as chaves não serão mais persistidas em arquivos.

    def generate_ephemeral_keys(self):
        """Gera um novo par de chaves RSA efêmeras e as armazena na instância."""
        key = RSA.generate(2048)
        self._private_key = key
        self._public_key = key.publickey()
        print("[RSAManager] Novo par de chaves RSA efêmeras gerado em memória.")

    def clear_keys(self):
        """Limpa as chaves RSA da memória."""
        self._private_key = None
        self._public_key = None
        print("[RSAManager] Chaves RSA efêmeras limpas da memória.")

    def get_public_key(self):
        """Retorna a chave pública efêmera atual."""
        if not self._public_key:
            raise ValueError("Chave pública não gerada. Chame generate_ephemeral_keys() primeiro.")
        return self._public_key

    def get_public_key_bytes(self):
        """Retorna a chave pública RSA efêmera em formato de bytes exportado."""
        if self._public_key:
            return self._public_key.export_key()
        return None

    def decrypt_token(self, encrypted_token: bytes) -> str:
        """Descriptografa token usando a chave privada efêmera interna."""
        if not self._private_key:
            raise ValueError("Chave privada RSA não carregada. Chame generate_ephemeral_keys() primeiro.")
        
        cipher = PKCS1_OAEP.new(self._private_key)
        return cipher.decrypt(encrypted_token).decode('utf-8')
    
    @classmethod # Este método pode permanecer @classmethod
    def encrypt_with_public_key(cls, data: bytes, public_key) -> bytes:
        """Criptografa dados usando uma chave pública fornecida."""
        if not public_key:
            raise ValueError("Chave pública não fornecida")
        
        cipher = PKCS1_OAEP.new(public_key)
        return cipher.encrypt(data)

    # O método _load_key_file não é mais necessário para o servidor,
    # mas pode ser útil para o cliente se ele precisar importar chaves de bytes.
    # Se o cliente só recebe bytes e importa diretamente, podemos remover este método.
    # Por enquanto, vamos mantê-lo como @classmethod para o cliente.
    @classmethod
    def _load_key_file(cls, key_data):
        """Carrega uma chave RSA a partir de dados em bytes."""
        if isinstance(key_data, bytes):
            return RSA.import_key(key_data)
        else:
            raise ValueError("key_data deve ser bytes da chave.")

# Exemplo de uso (apenas para demonstração da classe)
if __name__ == "__main__":
    manager = RSAManager()
    manager.generate_ephemeral_keys() # Gerar chaves
    pub_key = manager.get_public_key()
    
    message = b"TokenSecreto123"
    encrypted = manager.encrypt_with_public_key(message, pub_key)
    decrypted = manager.decrypt_token(encrypted)
    
    print(f"Original: {message.decode()}, Descriptografado: {decrypted}")
    manager.clear_keys() # Limpar chaves
    try:
        manager.decrypt_token(encrypted)
    except ValueError as e:
        print(f"Erro esperado após limpar chaves: {e}")
