import socket
from PySide6.QtCore import QObject, Signal, Slot
from src.core.chat.globals import clientes_lock, handlers, authenticated_ips, authenticated_ips_lock, encryption_keys, encryption_keys_lock
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from src.core.crypto.dh_params import load_dh_parameters

class ClientHandler(QObject):
    new_message_for_host = Signal(str)
    client_status_for_host = Signal(str)

    def __init__(self, client_socket, addr):
        super().__init__()
        self.client_socket = client_socket
        self.addr = addr
        self.username = f"[{addr[0]}]"
        self._running = True
        self.client_socket.settimeout(1.0)
        self.shared_key = None # Chave secreta compartilhada
        self.cipher = None     # Objeto Cipher AES
        self.nonce = None      # Nonce para AES-GCM

    def stop(self):
        self._running = False

    def _derive_key(self, shared_secret):
        # Derivar uma chave de 32 bytes (256 bits) para AES
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
            backend=default_backend()
        ).derive(shared_secret)

    def _encrypt_message(self, message: str) -> bytes:
        if not self.cipher or not self.nonce:
            raise Exception("Chave de criptografia ou nonce não inicializados.")

        encryptor = self.cipher.encryptor()
        ciphertext = encryptor.update(message.encode('utf-8')) + encryptor.finalize()
        tag = encryptor.tag # Tag de autenticação para GCM
        return self.nonce + tag + ciphertext # Enviar nonce, tag e ciphertext

    def _decrypt_message(self, encrypted_data: bytes) -> str:
        if not self.cipher:
            raise Exception("Chave de criptografia não inicializada.")

        # O nonce é enviado junto com a mensagem criptografada
        # Assumimos que o nonce tem 12 bytes para AES-GCM
        received_nonce = encrypted_data[:12]
        received_tag = encrypted_data[12:28] # Tag GCM tem 16 bytes
        ciphertext = encrypted_data[28:]

        decryptor = Cipher(
            algorithms.AES(self.shared_key),
            modes.GCM(received_nonce, received_tag), # Passar o nonce e a tag para o modo GCM
            backend=default_backend()
        ).decryptor()

        try:
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return plaintext.decode('utf-8')
        except Exception as e:
            print(f"[ClientHandler] Erro de descriptografia ou autenticação (GCM Tag inválida): {e}")
            return "[MENSAGEM CORROMPIDA OU NÃO AUTENTICADA]"


    @Slot()
    def run(self):
        with clientes_lock:
            handlers.append(self)
            self.client_status_for_host.emit(f"[ClientHandler] Cliente conectado: {self.addr}")

        try:
            # 1. Receber nome de usuário (como já existe)
            try:
                initial_message_bytes = self.client_socket.recv(1024)
                if initial_message_bytes:
                    initial_message = initial_message_bytes.decode('utf-8').strip()
                    if initial_message.startswith("__USERNAME__:"):
                        self.username = initial_message.split(":", 1)[1]
                        self.client_status_for_host.emit(f"[ClientHandler] Cliente '{self.username}' ({self.addr}) conectado.")
                    else:
                        print(f"[ClientHandler] Primeira mensagem inesperada de {self.addr}: {initial_message}")
                        self.new_message_for_host.emit(f"[ClientHandler] Mensagem inesperada de {self.addr}: {initial_message}")
                        return # Encerrar se a primeira mensagem não for o username
                else:
                    print(f"[ClientHandler] Cliente {self.addr} desconectou antes de enviar o nome.")
                    return
            except socket.timeout:
                print(f"[ClientHandler] Timeout ao esperar nome de usuário de {self.addr}. Usando IP.")
            except Exception as e:
                print(f"[ClientHandler] Erro ao receber nome de usuário de {self.addr}: {e}. Usando IP.")
                return 


            try:
                parameters = load_dh_parameters()
                self_private_key = parameters.generate_private_key()
                self_public_key_bytes = self_private_key.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                self.client_socket.sendall(self_public_key_bytes)
                self.client_status_for_host.emit(f"[ClientHandler] Chave pública enviada para {self.username}.")

                client_public_key_bytes = self.client_socket.recv(1024)
                if not client_public_key_bytes:
                    print(f"[ClientHandler] Cliente {self.username} desconectou durante a troca de chaves.")
                    return

                client_public_key = serialization.load_pem_public_key(
                    client_public_key_bytes,
                    backend=default_backend()
                )
                self.client_status_for_host.emit(f"[ClientHandler] Chave pública recebida de {self.username}.")

                self.shared_key = self_private_key.exchange(client_public_key)
                self.shared_key = self._derive_key(self.shared_key) # Derivar chave AES
                self.cipher = Cipher(algorithms.AES(self.shared_key), mode=None, backend=default_backend()) # Modo GCM será instanciado por mensagem
                self.client_status_for_host.emit(f"[ClientHandler] Chave secreta estabelecida com {self.username}.")

                with encryption_keys_lock:
                    encryption_keys[self.addr[0]] = {
                        'shared_key': self.shared_key,
                        'cipher': self.cipher # Armazenar o objeto Cipher base
                    }
                self.client_socket.sendall(b"KEY_EXCHANGE_SUCCESS") # Confirmar troca de chaves

            except Exception as e:
                print(f"[ClientHandler] Erro na troca de chaves Diffie-Hellman com {self.addr}: {e}")
                self.client_socket.sendall(b"KEY_EXCHANGE_FAILURE")
                return # Encerrar conexão se a troca de chaves falhar

            # 3. Loop de comunicação criptografada
            while self._running:
                try:
                    encrypted_message_bytes = self.client_socket.recv(2048) # Aumentar buffer para dados criptografados
                    if not encrypted_message_bytes:
                        print(f"[ClientHandler] Cliente {self.username} ({self.addr}) desconectou")
                        break

                    try:
                        mensagem = self._decrypt_message(encrypted_message_bytes)
                        self.new_message_for_host.emit(f"{self.username}: {mensagem}")
                        self.broadcast_message(f"{self.username}: {mensagem}", self.client_socket)
                    except Exception as decrypt_e:
                        print(f"[ClientHandler] Falha ao descriptografar mensagem de {self.username} ({self.addr}): {decrypt_e}")
                        self.new_message_for_host.emit(f"[ClientHandler] Mensagem criptografada inválida de {self.username} ({self.addr}).")


                except socket.timeout:
                    continue
                except Exception as e:
                    if self._running:
                        print(f"[ClientHandler] Erro com cliente {self.username} ({self.addr}): {e}")
                        self.new_message_for_host.emit(f"[ClientHandler] Erro com cliente {self.username} ({self.addr}): {e}")
                    break

        finally:
            with clientes_lock:
                if self in handlers:
                    handlers.remove(self)
                    print(f"[ClientHandler] Handler removido para {self.username} ({self.addr})")

            client_ip = self.addr[0]
            with authenticated_ips_lock:
                if client_ip in authenticated_ips:
                    authenticated_ips.remove(client_ip)
                    print(f"[ClientHandler] IP {client_ip} removido da lista de IPs autenticados. Lista atual: {authenticated_ips}")
            with encryption_keys_lock:
                if client_ip in encryption_keys:
                    del encryption_keys[client_ip]
                    print(f"[ClientHandler] Chave de criptografia para {client_ip} removida.")

            self.client_socket.close()
            self.client_status_for_host.emit(f"[ClientHandler] Cliente '{self.username}' desconectado.")
            print(f"[ClientHandler] Conexão encerrada com {self.username} ({self.addr})")

    def send_to_client(self, message: str):
        try:
            if self._running and self.shared_key: # Só envia se a chave estiver estabelecida
                encrypted_message = self._encrypt_message(message)
                self.client_socket.sendall(encrypted_message)
            elif self._running:
                print(f"[ClientHandler] Tentativa de enviar mensagem antes da troca de chaves para {self.username}.")
        except Exception as e:
            print(f"[ClientHandler] Erro ao enviar para {self.username} ({self.addr}): {e}")

    def broadcast_message(self, message: str, sender_socket=None):
        with clientes_lock:
            current_handlers = handlers.copy()

        for handler in current_handlers:
            if handler.client_socket != sender_socket and handler._running and handler.shared_key:
                try:
                    encrypted_message = handler._encrypt_message(message)
                    handler.client_socket.sendall(encrypted_message)
                except Exception as e:
                    print(f"[ClientHandler] Erro no broadcast para {handler.username} ({handler.addr}): {e}")
            elif handler.client_socket != sender_socket and handler._running:
                print(f"[ClientHandler] Pulando broadcast para {handler.username} (chave não estabelecida).")

# Importar serialização para chaves públicas
from cryptography.hazmat.primitives import serialization
