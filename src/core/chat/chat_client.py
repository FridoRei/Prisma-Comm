import socket
import threading
from PySide6.QtCore import QObject, Signal, Slot
from src.core.auth.rsa_manager import RSAManager # Para receber a chave pública do servidor
from src.core.crypto.aes_manager import AESManager # Para gerenciar a chave AES do cliente

class ChatClientWorker(QObject):
    message_received = Signal(str)
    connection_error = Signal(str)
    disconnected = Signal()

    def __init__(self, client_socket, aes_manager: AESManager):
        super().__init__()
        self.client_socket = client_socket
        self.aes_manager = aes_manager # A chave AES para este cliente
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
                # Recebe a mensagem criptografada (nonce + ciphertext + tag)
                encrypted_message_b64 = self.client_socket.recv(2048).decode('utf-8') # Aumentar buffer
                if not encrypted_message_b64:
                    self.message_received.emit("[CLIENT] Conexão perdida.")
                    self.disconnected.emit()
                    break

                if encrypted_message_b64 == "AUTH_REQUIRED": # Mensagem de erro do servidor
                    self.connection_error.emit("[CLIENT] Conexão recusada: Autenticação necessária. Por favor, autentique-se primeiro.")
                    self.disconnected.emit()
                    break

                parts = encrypted_message_b64.split('|')
                if len(parts) == 3:
                    nonce = AESManager.base64_to_bytes(parts[0])
                    ciphertext = AESManager.base64_to_bytes(parts[1])
                    tag = AESManager.base64_to_bytes(parts[2])

                    # Descriptografa a mensagem
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
    def __init__(self, host_ip, port, chat_widget=None, nome_usuario="Usuário"):
        self.host = host_ip
        self.port = port
        self.chat_widget = chat_widget
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.nome_usuario = nome_usuario
        self.worker = None
        self.thread = None
        self.aes_manager = AESManager() # Gerador de chave AES para este cliente

    def connect(self):
        if not self.host:
            print("[CLIENT] Gateway não encontrado, verifique sua rede.")
            return

        try:
            self.client_socket.connect((self.host, self.port))
            print(f"[CLIENT] Conectado ao servidor em {self.host}:{self.port}")

            # --- PASSO 1: Handshake de Chave AES (RSA para AES) ---
            # 1. Cliente recebe chave pública RSA do servidor
            server_rsa_public_key_bytes = self.client_socket.recv(2048)
            server_rsa_public_key = RSAManager._load_key_file(server_rsa_public_key_bytes)

            # 2. Cliente criptografa sua chave AES com a chave pública RSA do servidor
            aes_key_to_send = self.aes_manager.get_key()
            encrypted_aes_key = RSAManager.encrypt_with_public_key(aes_key_to_send, server_rsa_public_key)
            encrypted_aes_key_b64 = AESManager.bytes_to_base64(encrypted_aes_key)
            self.client_socket.sendall(encrypted_aes_key_b64.encode('utf-8'))

            # 3. Cliente espera confirmação do handshake AES
            handshake_response = self.client_socket.recv(1024).decode('utf-8')
            if handshake_response != "AES_HANDSHAKE_SUCCESS":
                raise Exception(f"Handshake AES falhou: {handshake_response}")
            print("[CLIENT] Handshake AES concluído com sucesso.")

            # Envia o nome de usuário (mantido)
            self.client_socket.sendall(f"__USERNAME__:{self.nome_usuario}\n".encode())

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
                # Se o worker não foi criado, a desconexão precisa ser tratada aqui
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

            # Criptografa a mensagem antes de enviar
            nonce, ciphertext, tag = self.aes_manager.encrypt(message)
            # Envia no formato nonce_b64|ciphertext_b64|tag_b64
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

