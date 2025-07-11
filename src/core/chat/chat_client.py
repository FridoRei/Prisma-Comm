import socket
import threading
from PySide6.QtCore import QObject, Signal, Slot
from src.core.network.connection_manager import obter_gateway
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from src.core.crypto.dh_params import load_dh_parameters

class ChatClientWorker(QObject):
    message_received = Signal(str)
    connection_error = Signal(str)
    disconnected = Signal()

    def __init__(self, client_socket, decrypt_func):
        super().__init__()
        self.client_socket = client_socket
        self.decrypt_func = decrypt_func # Função de descriptografia do ChatClient
        self._running = True

    def stop(self):
        self._running = False
        try:
            if self.client_socket:
                self.client_socket.shutdown(socket.SHUT_RDWR)
                self.client_socket.close()
                print("[CLIENT] Socket do worker fechado.")
        except Exception as e:
            print(f"[CLIENT] Erro ao fechar socket do worker: {e}")

    @Slot()
    def listen_for_messages(self):
        while self._running:
            try:
                encrypted_message = self.client_socket.recv(2048) # Aumentar buffer
                if encrypted_message:
                    if encrypted_message.decode('utf-8', errors='ignore') == "AUTH_REQUIRED":
                        self.connection_error.emit("[CLIENT] Conexão recusada: Autenticação necessária. Por favor, autentique-se primeiro.")
                        self.disconnected.emit()
                        break
                    try:
                        message = self.decrypt_func(encrypted_message)
                        self.message_received.emit(message)
                    except Exception as decrypt_e:
                        print(f"[CLIENT] Falha ao descriptografar mensagem: {decrypt_e}")
                        self.message_received.emit("[CLIENT] Mensagem criptografada inválida ou corrompida.")
                else:
                    self.message_received.emit("[CLIENT] Conexão perdida.")
                    self.disconnected.emit()
                    break
            except Exception as e:
                if self._running:
                    self.connection_error.emit(f"[CLIENT] Erro de conexão: {e}")
                self.disconnected.emit()
                break

        self.client_socket.close()
        print("[CLIENT] Thread de escuta encerrada.")


class ChatClient:
    def __init__(self, port, chat_widget=None, nome_usuario="Usuário"):
        self.host = obter_gateway()
        self.port = port
        self.chat_widget = chat_widget
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.nome_usuario = nome_usuario
        self.worker = None
        self.thread = None
        self.shared_key = None 
        self.cipher = None     

    def _derive_key(self, shared_secret):
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
            backend=default_backend()
        ).derive(shared_secret)

    def _encrypt_message(self, message: str) -> bytes:
        if not self.cipher:
            raise Exception("Chave de criptografia não inicializada.")

        nonce = os.urandom(12) # Gerar um nonce único para cada mensagem
        encryptor = Cipher(
            algorithms.AES(self.shared_key),
            modes.GCM(nonce),
            backend=default_backend()
        ).encryptor()

        ciphertext = encryptor.update(message.encode('utf-8')) + encryptor.finalize()
        tag = encryptor.tag
        return nonce + tag + ciphertext

    def _decrypt_message(self, encrypted_data: bytes) -> str:
        if not self.cipher:
            raise Exception("Chave de criptografia não inicializada.")

        received_nonce = encrypted_data[:12]
        received_tag = encrypted_data[12:28]
        ciphertext = encrypted_data[28:]

        decryptor = Cipher(
            algorithms.AES(self.shared_key),
            modes.GCM(received_nonce, received_tag),
            backend=default_backend()
        ).decryptor()

        try:
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return plaintext.decode('utf-8')
        except Exception as e:
            print(f"[CLIENT] Erro de descriptografia ou autenticação (GCM Tag inválida): {e}")
            raise # Propagar o erro para o worker lidar

    def connect(self):
        if not self.host:
            print("[CLIENT] Gateway não encontrado, verifique sua rede.")
            return

        try:
            self.client_socket.connect((self.host, self.port))
            print(f"[CLIENT] Conectado ao servidor em {self.host}:{self.port}")

            # 1. Enviar nome de usuário
            self.client_socket.sendall(f"__USERNAME__:{self.nome_usuario}\n".encode())

            # 2. Troca de chaves Diffie-Hellman
            parameters = load_dh_parameters()
            self_private_key = parameters.generate_private_key()
            self_public_key_bytes = self_private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            self.client_socket.sendall(self_public_key_bytes)
            print("[CLIENT] Chave pública enviada para o servidor.")

            server_public_key_bytes = self.client_socket.recv(1024)
            if not server_public_key_bytes:
                raise Exception("Servidor desconectou durante a troca de chaves.")

            server_public_key = serialization.load_pem_public_key(
                server_public_key_bytes,
                backend=default_backend()
            )
            print("[CLIENT] Chave pública recebida do servidor.")

            self.shared_key = self_private_key.exchange(server_public_key)
            self.shared_key = self._derive_key(self.shared_key) # Derivar chave AES
            self.cipher = Cipher(algorithms.AES(self.shared_key), mode=None, backend=default_backend()) # Modo GCM será instanciado por mensagem
            print("[CLIENT] Chave secreta estabelecida com o servidor.")

            key_exchange_status = self.client_socket.recv(1024).decode('utf-8').strip()
            if key_exchange_status != "KEY_EXCHANGE_SUCCESS":
                raise Exception(f"Falha na troca de chaves com o servidor: {key_exchange_status}")

            # 3. Iniciar worker para escutar mensagens criptografadas
            self.worker = ChatClientWorker(self.client_socket, self._decrypt_message)
            self.thread = threading.Thread(target=self.worker.listen_for_messages, daemon=True)
            self.thread.start()

        except Exception as e:
            print(f"[CLIENT] Erro ao estabelecer conexão ou troca de chaves: {e}")
            if self.chat_widget:
                self.chat_widget.add_message_to_chat(f"[CLIENT] Erro ao conectar: {e}")
            if self.worker:
                self.worker.disconnected.emit()
            self.client_socket.close() # Fechar o socket em caso de erro na conexão/troca de chaves

    def send_message(self, message):
        try:
            if not self.client_socket or not self.shared_key:
                raise Exception("[CLIENT] Socket ou chave de criptografia não inicializados.")

            encrypted_message = self._encrypt_message(message)
            self.client_socket.sendall(encrypted_message)
        except Exception as e:
            print(f"[CLIENT] Erro ao enviar mensagem: {e}")
            if self.chat_widget:
                self.chat_widget.add_message_to_chat(f"[CLIENT] Erro ao enviar: {e}")
            raise

    def disconnect(self):
        if self.worker:
            self.worker.stop()
        print("[CLIENT] Cliente desconectado.")

# Importar serialização e os para geração de nonce
from cryptography.hazmat.primitives import serialization
import os
