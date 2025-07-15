import socket
import threading
from PySide6.QtCore import QObject, Signal, Slot
from src.core.crypto.ecc_manager import ECCManager
from src.core.crypto.aes_manager import AESManager 

class ChatClientWorker(QObject):
    message_received = Signal(str)
    connection_error = Signal(str)
    disconnected = Signal()
    specific_error = Signal(str)

    def __init__(self, client_socket, aes_manager: AESManager):
        super().__init__()
        self.client_socket = client_socket
        self.aes_manager = aes_manager
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
                encrypted_message_b64 = self.client_socket.recv(4096).decode('utf-8') 
                if not encrypted_message_b64:
                    self.message_received.emit("[CLIENT] Conexão perdida.")
                    self.disconnected.emit()
                    break

                if not encrypted_message_b64.startswith(f"{ECCManager.bytes_to_base64(b'')}"):
                    if encrypted_message_b64 == "AUTH_REQUIRED": 
                        self.specific_error.emit("[CLIENT] Conexão recusada: Autenticação necessária. Por favor, autentique-se primeiro.")
                        self.disconnected.emit()
                        break
                    elif encrypted_message_b64 == "ECC_HANDSHAKE_FAILURE":
                        self.specific_error.emit("[CLIENT] Handshake de criptografia falhou com o servidor.")
                        self.disconnected.emit()
                        break
                    else:
                        self.message_received.emit(f"[SERVER INFO] {encrypted_message_b64}")
                        continue 

                parts = encrypted_message_b64.split('|')
                if len(parts) == 3:
                    nonce = AESManager.base64_to_bytes(parts[0])
                    ciphertext = AESManager.base64_to_bytes(parts[1])
                    tag = AESManager.base64_to_bytes(parts[2])

                    try:
                        message = self.aes_manager.decrypt(nonce, ciphertext, tag)
                        self.message_received.emit(message)
                    except Exception as e:
                        self.connection_error.emit(f"[CLIENT] ERRO ao descriptografar mensagem: {e}")
                        print(f"[CLIENT] ERRO ao descriptografar mensagem: {e}")
                else:
                    self.connection_error.emit(f"[CLIENT] Formato de mensagem inválido recebido.")
                    print(f"[CLIENT] Formato de mensagem inválido recebido: {encrypted_message_b64}")

            except Exception as e:
                if self._running:
                    self.connection_error.emit(f"[CLIENT] Erro de conexão: {e}")
                self.disconnected.emit()
                break

        self.client_socket.close()
        print("[CLIENT] Thread de escuta encerrada.")

class ChatClient:
    def __init__(self, host_ip, port, chat_widget=None, nome_usuario="Usuário", ecc_manager=None): 
        self.host = host_ip
        self.port = port
        self.chat_widget = chat_widget
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.nome_usuario = nome_usuario
        self.worker = None
        self.thread = None
        self.aes_manager = AESManager()
        self.ecc_manager = ecc_manager

    def connect(self):
        if not self.host:
            print("[CLIENT] Gateway não encontrado, verifique sua rede.")
            return

        try:
            self.client_socket.connect((self.host, self.port))
            print(f"[CLIENT] Conectado ao servidor em {self.host}:{self.port}")

            server_handshake_data_b64 = self.client_socket.recv(4096).decode('utf-8') 
            parts = server_handshake_data_b64.split('|')
            if len(parts) != 3:
                raise ValueError("Formato de handshake do servidor inválido.")
            
            server_x25519_public_b64 = parts[0]
            server_signature_b64 = parts[1]
            host_ed25519_public_b64 = parts[2] 

            server_x25519_public_bytes = ECCManager.base64_to_bytes(server_x25519_public_b64)
            server_signature_bytes = ECCManager.base64_to_bytes(server_signature_b64)
            host_ed25519_public_bytes = ECCManager.base64_to_bytes(host_ed25519_public_b64)

            print("[CLIENT] Chaves X25519 e Ed25519 do servidor recebidas.")

            if not self.ecc_manager.has_ed25519_public_key():
                raise Exception("Nenhuma chave pública Ed25519 carregada para verificar a assinatura do servidor.")
            
            if not ECCManager.verify_signature(host_ed25519_public_bytes, server_x25519_public_bytes, server_signature_bytes):
                raise Exception("Falha na verificação da assinatura da chave X25519 do servidor.")
            print("[CLIENT] Assinatura da chave X25519 do servidor verificada com sucesso.")

            self.ecc_manager.generate_x25519_keys()
            client_x25519_public_bytes = self.ecc_manager.get_x25519_public_key_bytes()

            if not self.ecc_manager.has_ed25519_private_key():
                raise Exception("Nenhuma chave privada Ed25519 carregada para assinar a chave X25519 do cliente.")
            client_signature = self.ecc_manager.sign_data(client_x25519_public_bytes)
            
            client_ed25519_public_bytes = self.ecc_manager.get_ed25519_public_key_pem()
            response_data = f"{ECCManager.bytes_to_base64(client_x25519_public_bytes)}|{ECCManager.bytes_to_base64(client_signature)}|{ECCManager.bytes_to_base64(client_ed25519_public_bytes)}"
            self.client_socket.sendall(response_data.encode('utf-8'))
            print("[CLIENT] Chaves X25519 e Ed25519 do cliente enviadas.")

            derived_aes_key = self.ecc_manager.derive_shared_key(server_x25519_public_bytes)
            self.aes_manager = AESManager(derived_aes_key)
            print("[CLIENT] Chave AES derivada.")

            self.ecc_manager.clear_x25519_keys()

            handshake_response = self.client_socket.recv(1024).decode('utf-8')
            if handshake_response != "ECC_HANDSHAKE_SUCCESS":
                raise Exception(f"Handshake ECC falhou: {handshake_response}")
            print("[CLIENT] Handshake ECC concluído com sucesso.")

            nonce_username, ciphertext_username, tag_username = self.aes_manager.encrypt(self.nome_usuario)
            encrypted_username_b64 = f"{AESManager.bytes_to_base64(nonce_username)}|{AESManager.bytes_to_base64(ciphertext_username)}|{AESManager.bytes_to_base64(tag_username)}"
            self.client_socket.sendall(encrypted_username_b64.encode('utf-8'))

            self.worker = ChatClientWorker(self.client_socket, self.aes_manager)
            self.thread = threading.Thread(target=self.worker.listen_for_messages, daemon=True)
            self.thread.start()
        except Exception as e:
            print(f"[CLIENT] Erro ao estabelecer conexão ou handshake: {e}")
            if self.chat_widget:
                self.chat_widget.add_message_to_chat(f"[CLIENT] Erro ao conectar: {e}")

            if self.worker:
                self.worker.disconnected.emit()
            else:
                if self.client_socket:
                    try:
                        self.client_socket.close()
                    except Exception as close_e:
                        print(f"[CLIENT] Erro ao fechar socket após falha de conexão: {close_e}")
                if self.chat_widget:
                    self.chat_widget.add_message_to_chat("[CLIENT] Conexão falhou antes de iniciar o worker.")


    def send_message(self, message):
        try:
            if not self.client_socket:
                raise Exception("[CLIENT] Socket não inicializado.")
            if not self.aes_manager:
                raise Exception("[CLIENT] Chave AES não estabelecida.")

            nonce, ciphertext, tag = self.aes_manager.encrypt(message)
            encrypted_data_b64 = f"{AESManager.bytes_to_base64(nonce)}|{AESManager.bytes_to_base64(ciphertext)}|{AESManager.bytes_to_base64(tag)}"
            
            self.client_socket.sendall(encrypted_data_b64.encode())
        except Exception as e:
            print(f"[CLIENT] Erro ao enviar mensagem: {e}")
            if self.chat_widget:
                self.chat_widget.add_message_to_chat(f"[CLIENT] Erro ao enviar: {e}")
            raise

    def disconnect(self):
        if self.worker:
            self.worker.stop()
        print("[CLIENT] Cliente desconectado.")

