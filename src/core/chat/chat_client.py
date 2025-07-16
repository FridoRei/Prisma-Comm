import socket
import threading
from PySide6.QtCore import QObject, Signal, Slot
from src.core.crypto.ecc_manager import ECCManager
from src.core.crypto.aes_manager import AESManager 

class ChatClientWorker(QObject):
    message_received = Signal(str)
    connection_error = Signal(str)
    disconnected = Signal() # Signal to indicate disconnection
    specific_error = Signal(str) # Signal for specific error messages (e.g., AUTH_REQUIRED)

    def __init__(self, client_socket, aes_manager: AESManager):
        super().__init__()
        self.client_socket = client_socket
        self.aes_manager = aes_manager
        self._running = True

    def stop(self):
        self._running = False
        try:
            if self.client_socket:
                # Attempt to shutdown gracefully before closing
                self.client_socket.shutdown(socket.SHUT_RDWR)
                self.client_socket.close()
                print("[INFO] [ChatClientWorker] Socket do worker fechado.")
        except OSError as e:
            # Error 107 is "Transport endpoint is not connected" on Linux,
            # which can happen if the socket is already closed or not fully connected.
            # It's often safe to ignore during shutdown.
            if e.errno != 107: 
                print(f"[ERROR] [ChatClientWorker] Erro ao fechar socket do worker: {e}")
        except Exception as e:
            print(f"[CRITICAL] [ChatClientWorker] Erro inesperado ao fechar socket do worker: {e}")

    @Slot()
    def listen_for_messages(self):
        while self._running:
            try:
                encrypted_message_b64 = self.client_socket.recv(8192).decode('utf-8') 
                if not encrypted_message_b64:
                    self.message_received.emit("[INFO] Conexão perdida com o servidor.")
                    print("[INFO] [ChatClientWorker] Conexão perdida com o servidor (dados vazios recebidos).")
                    self.disconnected.emit() # Emit disconnected signal
                    break

                # Check if it's a control message (not in the encrypted format)
                parts = encrypted_message_b64.split('|')
                if len(parts) != 3: 
                    if encrypted_message_b64 == "AUTH_REQUIRED": 
                        self.specific_error.emit("[ERROR] Conexão recusada: Autenticação necessária. Por favor, autentique-se primeiro.")
                        print("[WARNING] [ChatClientWorker] Servidor exigiu autenticação.")
                        self.disconnected.emit()
                        break
                    elif encrypted_message_b64 == "ECC_HANDSHAKE_FAILURE":
                        self.specific_error.emit("[ERROR] Handshake de criptografia falhou com o servidor.")
                        print("[ERROR] [ChatClientWorker] Handshake ECC falhou com o servidor.")
                        self.disconnected.emit()
                        break
                    else:
                        # Generic server info message
                        self.message_received.emit(f"[SERVER INFO] {encrypted_message_b64}")
                        print(f"[INFO] [ChatClientWorker] Mensagem de controle do servidor: {encrypted_message_b64}")
                        continue 

                # Attempt to decrypt if it's in the expected format
                try:
                    nonce = AESManager.base64_to_bytes(parts[0])
                    ciphertext = AESManager.base64_to_bytes(parts[1])
                    tag = AESManager.base64_to_bytes(parts[2])

                    message = self.aes_manager.decrypt(nonce, ciphertext, tag)
                    self.message_received.emit(message)
                except Exception as e:
                    self.connection_error.emit(f"[ERROR] ERRO ao descriptografar mensagem. Possível chave incorreta ou mensagem corrompida.")
                    print(f"[ERROR] [ChatClientWorker] ERRO ao descriptografar mensagem: {e}. Conteúdo: {encrypted_message_b64[:100]}...") 
                
            except socket.timeout:
                continue
            except ConnectionResetError:
                self.message_received.emit("[ERROR] Conexão reiniciada pelo servidor. Desconectado.")
                print("[ERROR] [ChatClientWorker] Conexão reiniciada pelo servidor.")
                self.disconnected.emit()
                break
            except UnicodeDecodeError:
                self.connection_error.emit("[ERROR] Erro de decodificação de caracteres na mensagem recebida.")
                print(f"[ERROR] [ChatClientWorker] Erro de decodificação Unicode na mensagem recebida. Dados brutos: {self.client_socket.recv(8192, socket.MSG_PEEK).hex()}") 
                self.disconnected.emit() 
                break
            except Exception as e:
                if self._running: # Only log if the worker is still supposed to be running
                    self.connection_error.emit(f"[ERROR] Erro de conexão inesperado. Por favor, reconecte.")
                    print(f"[CRITICAL] [ChatClientWorker] Erro inesperado na thread de escuta: {e}")
                self.disconnected.emit() # Always emit disconnected on unexpected errors
                break

        # Ensure socket is closed when the listening loop ends
        try:
            self.client_socket.close()
        except Exception as e:
            print(f"[ERROR] [ChatClientWorker] Erro ao fechar socket no final da thread: {e}")
        print("[INFO] [ChatClientWorker] Thread de escuta encerrada.")

class ChatClient:
    def __init__(self, host_ip, port, chat_widget=None, nome_usuario="Usuário", ecc_manager=None, client_ed25519_public_key_bytes: bytes = None):
        self.host = host_ip
        self.port = port
        self.chat_widget = chat_widget 
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.nome_usuario = nome_usuario
        self.worker = None
        self.thread = None # Initialize thread to None
        self.aes_manager = AESManager() 
        self.ecc_manager = ecc_manager
        self.client_ed25519_public_key_bytes = client_ed25519_public_key_bytes

    def connect(self):
        if not self.host:
            print("[ERROR] [ChatClient] Gateway não encontrado. Verifique sua rede ou insira o IP manualmente.")
            if self.chat_widget:
                self.chat_widget.add_message_to_chat("[ERROR] Gateway não encontrado. Verifique sua rede.")
            return False # Return False on failure

        try:
            print(f"[INFO] [ChatClient] Tentando conectar ao servidor em {self.host}:{self.port}...")
            self.client_socket.connect((self.host, self.port))
            print(f"[SUCCESS] [ChatClient] Conectado ao servidor em {self.host}:{self.port}")

            print("[INFO] [ChatClient] Iniciando handshake ECC...")
            server_handshake_data_b64 = self.client_socket.recv(4096).decode('utf-8')
            parts = server_handshake_data_b64.split('|')
            if len(parts) != 2: # Expecting 2 parts now
                raise ValueError(f"Formato de handshake do servidor inválido. Partes esperadas: 2, recebidas: {len(parts)}. Dados: {server_handshake_data_b64[:100]}...")

            server_x25519_public_b64 = parts[0]
            server_signature_b64 = parts[1]

            server_x25519_public_bytes = ECCManager.base64_to_bytes(server_x25519_public_b64)
            server_signature_bytes = AESManager.base64_to_bytes(server_signature_b64)  

            print("[INFO] [ChatClient] Chave X25519 e assinatura do servidor recebidas.")

            if not self.client_ed25519_public_key_bytes:
                raise Exception("Nenhuma chave pública Ed25519 do cliente fornecida para verificar a assinatura do servidor. Autenticação do servidor falhou.")

            print("[INFO] [ChatClient] Verificando assinatura da chave X25519 do servidor...")
            if not ECCManager.verify_signature(self.client_ed25519_public_key_bytes, server_x25519_public_bytes, server_signature_bytes):
                raise Exception("Falha na verificação da assinatura da chave X25519 do servidor. A chave do servidor pode ser inválida ou ter sido adulterada.")
            print("[SUCCESS] [ChatClient] Assinatura da chave X25519 do servidor verificada com sucesso.")

            self.ecc_manager.generate_x25519_keys()
            client_x25519_public_bytes = self.ecc_manager.get_x25519_public_key_bytes()

            response_data = f"{ECCManager.bytes_to_base64(client_x25519_public_bytes)}"
            self.client_socket.sendall(response_data.encode('utf-8'))
            print("[INFO] [ChatClient] Chave X25519 do cliente enviada.")

            derived_aes_key = self.ecc_manager.derive_shared_key(server_x25519_public_bytes)
            self.aes_manager = AESManager(derived_aes_key)
            print("[INFO] [ChatClient] Chave AES derivada com sucesso.")

            self.ecc_manager.clear_x25519_keys() 

            handshake_response = self.client_socket.recv(1024).decode('utf-8')
            if handshake_response != "ECC_HANDSHAKE_SUCCESS":
                raise Exception(f"Handshake ECC falhou. Resposta do servidor: '{handshake_response}'")
            print("[SUCCESS] [ChatClient] Handshake ECC concluído com sucesso.")

            print("[INFO] [ChatClient] Enviando nome de usuário criptografado...")
            nonce_username, ciphertext_username, tag_username = self.aes_manager.encrypt(self.nome_usuario)
            encrypted_username_b64 = f"{AESManager.bytes_to_base64(nonce_username)}|{AESManager.bytes_to_base64(ciphertext_username)}|{AESManager.bytes_to_base64(tag_username)}"
            self.client_socket.sendall(encrypted_username_b64.encode('utf-8'))
            print("[INFO] [ChatClient] Nome de usuário enviado.")

            # --- CORREÇÃO AQUI: Conectar sinais ao chat_widget e à MainWindow ---
            self.worker = ChatClientWorker(self.client_socket, self.aes_manager)
            
            # Conectar sinais do worker ao chat_widget para mensagens e erros de conexão
            if self.chat_widget:
                self.worker.message_received.connect(self.chat_widget.add_message_to_chat)
                self.worker.connection_error.connect(self.chat_widget.add_message_to_chat)
                # Os sinais 'disconnected' e 'specific_error' devem ser conectados à MainWindow
                # ou a um gerenciador de estado que possa reagir a eles.
                # O AppService já faz isso, então vamos garantir que o AppService os conecte.
                # Não conecte aqui ao chat_widget.disconnected/specific_error, pois eles não existem.
            
            self.thread = threading.Thread(target=self.worker.listen_for_messages, daemon=True)
            self.thread.start()
            print("[INFO] [ChatClient] Thread de escuta iniciada.")
            return True # Return True on successful connection and worker start

        except socket.timeout:
            print(f"[ERROR] [ChatClient] Timeout ao tentar conectar ou durante o handshake com {self.host}:{self.port}.")
            if self.chat_widget:
                self.chat_widget.add_message_to_chat(f"[ERROR] Erro de conexão: Timeout. O servidor não respondeu.")
        except ConnectionRefusedError:
            print(f"[ERROR] [ChatClient] Conexão recusada por {self.host}:{self.port}. Verifique se o servidor está ativo e as portas corretas.")
            if self.chat_widget:
                self.chat_widget.add_message_to_chat(f"[ERROR] Erro de conexão: Conexão recusada. Servidor pode estar offline.")
        except ValueError as e:
            print(f"[ERROR] [ChatClient] Erro de formato de dados durante o handshake: {e}")
            if self.chat_widget:
                self.chat_widget.add_message_to_chat(f"[ERROR] Erro de comunicação: Dados inválidos recebidos do servidor.")
        except Exception as e:
            print(f"[CRITICAL] [ChatClient] Erro inesperado ao estabelecer conexão ou handshake: {e}")
            if self.chat_widget:
                self.chat_widget.add_message_to_chat(f"[CRITICAL] Erro fatal ao conectar: {e}. Tente novamente.")

            # Ensure proper cleanup if connection fails before worker starts
            # If worker was created, emit its disconnected signal
            if self.worker:
                self.worker.disconnected.emit() 
            else: # If worker was not created, close the socket directly
                if self.client_socket:
                    try:
                        self.client_socket.close()
                        print("[INFO] [ChatClient] Socket fechado após falha de conexão.")
                    except Exception as close_e:
                        print(f"[ERROR] [ChatClient] Erro ao fechar socket após falha de conexão: {close_e}")
                if self.chat_widget:
                    self.chat_widget.add_message_to_chat("[ERROR] Conexão falhou antes de iniciar o worker.")
        return False # Return False on any exception during connection

    def send_message(self, message):
        try:
            if not self.client_socket:
                raise Exception("Socket não inicializado. Conecte-se primeiro.")
            if not self.aes_manager:
                raise Exception("Chave AES não estabelecida. Handshake ECC falhou?")

            nonce, ciphertext, tag = self.aes_manager.encrypt(message)
            encrypted_data_b64 = f"{AESManager.bytes_to_base64(nonce)}|{AESManager.bytes_to_base64(ciphertext)}|{AESManager.bytes_to_base64(tag)}"
            
            self.client_socket.sendall(encrypted_data_b64.encode())
        except BrokenPipeError:
            print(f"[ERROR] [ChatClient] Conexão quebrada ao tentar enviar mensagem. Servidor pode ter desconectado.")
            if self.chat_widget:
                self.chat_widget.add_message_to_chat(f"[ERROR] Erro ao enviar: Conexão perdida com o servidor.")
        except Exception as e:
            print(f"[ERROR] [ChatClient] Erro ao enviar mensagem: {e}")
            if self.chat_widget:
                self.chat_widget.add_message_to_chat(f"[ERROR] Erro ao enviar: {e}")
            raise

    def disconnect(self):
        if self.worker:
            self.worker.stop()
            if self.thread and self.thread.is_alive():
                self.thread.join(timeout=1) 
                if self.thread.is_alive():
                    print("[WARNING] [ChatClient] Thread do worker não encerrou em tempo.")
        try:
            if self.client_socket:
                self.client_socket.close()
                print("[INFO] [ChatClient] Socket do cliente principal fechado.")
        except Exception as e:
            print(f"[ERROR] [ChatClient] Erro ao fechar socket do cliente principal: {e}")
        print("[INFO] [ChatClient] Cliente desconectado.")

