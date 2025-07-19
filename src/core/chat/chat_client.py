import socket
import threading
from PySide6.QtCore import QObject, Signal, Slot
from src.core.crypto.ecc_manager import ECCManager
from src.core.crypto.aes_manager import AESManager
import os
import json
import hashlib
import mimetypes 

class ChatClientWorker(QObject):
    message_received = Signal(str)
    connection_error = Signal(str)
    disconnected = Signal()
    specific_error = Signal(str)
    file_received = Signal(str, str, bytes, str) 

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
                print("[INFO] [ChatClientWorker] Socket do worker fechado.")
        except OSError as e:
            if e.errno != 107:
                print(f"[ERROR] [ChatClientWorker] Erro ao fechar socket do worker: {e}")
        except Exception as e:
            print(f"[CRITICAL] [ChatClientWorker] Erro inesperado ao fechar socket do worker: {e}")

    @Slot()
    def listen_for_messages(self):
        while self._running:
            try:               
                header_bytes = self.client_socket.recv(4, socket.MSG_PEEK)
                if not header_bytes:
                    self.message_received.emit("[INFO] Conexão perdida com o servidor.")
                    print("[INFO] [ChatClientWorker] Conexão perdida com o servidor (dados vazios recebidos).")
                    self.disconnected.emit()
                    break

                try:
                    data_length = int.from_bytes(header_bytes, 'big')
                    if data_length > 0 and data_length <= 10 * 1024 * 1024 + 4096:
                        self.client_socket.recv(4)
                        self._handle_incoming_file(data_length)
                        continue
                except ValueError:
                    pass

                encrypted_data_b64 = self.client_socket.recv(8192).decode('utf-8')
                if not encrypted_data_b64:
                    self.message_received.emit("[INFO] Conexão perdida com o servidor.")
                    print("[INFO] [ChatClientWorker] Conexão perdida com o servidor (dados vazios recebidos).")
                    self.disconnected.emit()
                    break

                parts = encrypted_data_b64.split('|')
                if len(parts) != 3:
                    if encrypted_data_b64 == "AUTH_REQUIRED":
                        self.specific_error.emit("Conexão recusada: Autenticação necessária. Por favor, autentique-se primeiro.")
                        print("[WARNING] [ChatClientWorker] Servidor exigiu autenticação.")
                        self.disconnected.emit()
                        break
                    elif encrypted_data_b64 == "ECC_HANDSHAKE_FAILURE":
                        self.specific_error.emit("Erro de segurança: Handshake de criptografia falhou com o servidor.")
                        print("[ERROR] [ChatClientWorker] Handshake ECC falhou com o servidor.")
                        self.disconnected.emit()
                        break
                    else:
                        self.message_received.emit(f"[SERVER INFO] {encrypted_data_b64}")
                        print(f"[INFO] [ChatClientWorker] Mensagem de controle do servidor: {encrypted_data_b64}")
                        continue

                try:
                    nonce = AESManager.base64_to_bytes(parts[0])
                    ciphertext = AESManager.base64_to_bytes(parts[1])
                    tag = AESManager.base64_to_bytes(parts[2])

                    decrypted_json_str = self.aes_manager.decrypt(nonce, ciphertext, tag)
                    message_data = json.loads(decrypted_json_str)

                    msg_type = message_data.get("type")
                    msg_content = message_data.get("content")
                    msg_hash = message_data.get("hash")
                    sender_username = message_data.get("sender_username", "Desconhecido")

                    if msg_type == "text_message" and msg_content and msg_hash:
                        calculated_hash = hashlib.sha256(msg_content.encode('utf-8')).hexdigest()
                        if calculated_hash != msg_hash:
                            print(f"[ERROR] [ChatClientWorker] Erro de integridade na mensagem de {sender_username}. Hash inválido.")
                            self.message_received.emit(f"[ERRO] Falha na integridade da mensagem de {sender_username}.")
                            continue

                        self.message_received.emit(f"{sender_username}: {msg_content}")
                    else:
                        print(f"[WARNING] [ChatClientWorker] Formato de mensagem JSON inválido ou tipo desconhecido: {message_data}")
                        self.message_received.emit(f"[ERRO] Mensagem recebida em formato inválido.")

                except json.JSONDecodeError:
                    self.connection_error.emit("Erro ao decodificar JSON da mensagem. Mensagem corrompida.")
                    print(f"[ERROR] [ChatClientWorker] Erro ao decodificar JSON: {decrypted_json_str[:100]}...")
                except Exception as e:
                    self.connection_error.emit("Erro ao descriptografar ou processar mensagem. A mensagem pode estar corrompida ou a chave incorreta.")
                    print(f"[ERROR] [ChatClientWorker] ERRO ao descriptografar/processar mensagem: {e}. Conteúdo: {encrypted_data_b64[:100]}...")

            except socket.timeout:
                continue
            except ConnectionResetError:
                self.message_received.emit("Conexão reiniciada pelo servidor. Você foi desconectado.")
                print("[ERROR] [ChatClientWorker] Conexão reiniciada pelo servidor.")
                self.disconnected.emit()
                break
            except UnicodeDecodeError:
                self.connection_error.emit("Erro de comunicação: Dados inválidos recebidos.")
                print(f"[ERROR] [ChatClientWorker] Erro de decodificação Unicode na mensagem recebida. Dados brutos: {self.client_socket.recv(8192, socket.MSG_PEEK).hex()}")
                self.disconnected.emit()
                break
            except Exception as e:
                if self._running:
                    self.connection_error.emit("Erro de conexão inesperado. Por favor, reconecte.")
                    print(f"[CRITICAL] [ChatClientWorker] Erro inesperado na thread de escuta: {e}")
                self.disconnected.emit()
                break

        try:
            self.client_socket.close()
        except Exception as e:
            print(f"[ERROR] [ChatClientWorker] Erro ao fechar socket no final da thread: {e}")
        print("[INFO] [ChatClientWorker] Thread de escuta encerrada.")

    def _handle_incoming_file(self, total_data_length: int):
        try:
            encrypted_full_data = b''
            bytes_received = 0
            while bytes_received < total_data_length:
                chunk = self.client_socket.recv(min(total_data_length - bytes_received, 4096))
                if not chunk:
                    print("[WARNING] [ChatClientWorker] Conexão perdida durante o recebimento do arquivo.")
                    self.disconnected.emit()
                    return
                encrypted_full_data += chunk
                bytes_received += len(chunk)
            print(f"[DEBUG] [ChatClientWorker] Arquivo recebido. Tamanho total criptografado: {len(encrypted_full_data)} bytes. Hash dos dados criptografados: {hashlib.sha256(encrypted_full_data).hexdigest()}")

            parts = encrypted_full_data.split(b'<-->', 2)
            if len(parts) != 3:
                raise ValueError("Formato de dados de arquivo criptografado inválido.")

            nonce = parts[0]
            ciphertext = parts[1]
            tag = parts[2]

            decrypted_data_json_str = self.aes_manager.decrypt(nonce, ciphertext, tag)
            file_data = json.loads(decrypted_data_json_str)

            msg_type = file_data.get("type")
            original_filename = file_data.get("filename")
            mime_type = file_data.get("mime_type")
            file_content_b64 = file_data.get("content")
            received_hash = file_data.get("hash")
            sender_username = file_data.get("sender_username", "Desconhecido")

            if msg_type != "archive" or not all([original_filename, mime_type, file_content_b64, received_hash]):
                raise ValueError("Dados de arquivo incompletos, corrompidos ou tipo inválido.")

            file_content_bytes = AESManager.base64_to_bytes(file_content_b64)

            calculated_hash = hashlib.sha256(file_content_bytes).hexdigest()
            if calculated_hash != received_hash:
                print(f"[ERROR] [ChatClientWorker] Erro de integridade no arquivo '{original_filename}'. Hash inválido.")
                self.message_received.emit(f"[ERRO] Falha na integridade do arquivo '{original_filename}' de {sender_username}.")
                return

            print(f"[INFO] [ChatClientWorker] Arquivo '{original_filename}' ({mime_type}) recebido e verificado de {sender_username}.")
            self.file_received.emit(original_filename, mime_type, file_content_bytes, sender_username)

        except json.JSONDecodeError:
            print(f"[ERROR] [ChatClientWorker] Erro ao decodificar JSON do arquivo recebido.")
            self.message_received.emit(f"[ERRO] Erro ao receber arquivo: Dados corrompidos.")
        except Exception as e:
            print(f"[ERROR] [ChatClientWorker] Erro ao lidar com arquivo recebido: {e}")
            self.message_received.emit(f"[ERRO] Erro ao receber arquivo: {e}")

class ChatClient:
    def __init__(self, host_ip, port, chat_widget=None, nome_usuario="Usuário", ecc_manager=None, session_aes_key: bytes = None, recive_timeout: int = 1, handshake_timeout: int = 5):
        self.host = host_ip
        self.port = port
        self.chat_widget = chat_widget
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.nome_usuario = nome_usuario
        self.worker = None
        self.thread = None
        self.aes_manager = AESManager(session_aes_key)
        self.ecc_manager = ecc_manager
        self.recive_timeout = recive_timeout
        self.handshake_timeout = handshake_timeout

    def connect(self):
        if not self.host:
            print("[ERROR] [ChatClient] Gateway não encontrado. Verifique sua rede ou insira o IP manualmente.")
            if self.chat_widget:
                self.chat_widget.add_message_to_chat("[ERROR] Gateway não encontrado. Verifique sua rede.")
            return False
        try:
            print(f"[INFO] [ChatClient] Tentando conectar ao servidor em {self.host}:{self.port}...")
            self.client_socket.settimeout(self.handshake_timeout)
            self.client_socket.connect((self.host, self.port))
            print(f"[SUCCESS] [ChatClient] Conectado ao servidor em {self.host}:{self.port}")

            initial_response_b64 = self.client_socket.recv(1024).decode('utf-8').strip()
            try:
                parts = initial_response_b64.split('|')
                if len(parts) == 3:
                    nonce = AESManager.base64_to_bytes(parts[0])
                    ciphertext = AESManager.base64_to_bytes(parts[1])
                    tag = AESManager.base64_to_bytes(parts[2])
                    decrypted_response = self.aes_manager.decrypt(nonce, ciphertext, tag)
                    if decrypted_response == "ACCEPTED":
                        print(f"[INFO] [ChatClient] Servidor de chat aceitou a conexão.")
                    else:
                        raise Exception(f"Resposta inicial criptografada inesperada do servidor de chat: '{decrypted_response}'")
                else:
                    if initial_response_b64 == "AUTH_REQUIRED":
                        raise Exception("Conexão recusada pelo servidor de chat: Autenticação necessária (erro inesperado).")
                    elif initial_response_b64 == "REFUSED":
                        raise Exception("Conexão recusada pelo servidor de chat (DoS ou já conectado).")
                    elif initial_response_b64 == "ERROR_ENCRYPTING_ACCEPTED":
                        raise Exception(f"Resposta inicial criptografada inesperada do servidor de chat: '{decrypted_response}'")
            except Exception as e:
                print(f"[ERROR] [ChatClient] Erro ao processar resposta inicial do servidor: {e}")
                raise

            username_data = {
                "type": "username_init", 
                "content": self.nome_usuario,
                "hash": hashlib.sha256(self.nome_usuario.encode('utf-8')).hexdigest()
            }
            encrypted_username_json_str = json.dumps(username_data)
            nonce_username, ciphertext_username, tag_username = self.aes_manager.encrypt(encrypted_username_json_str)
            encrypted_username_b64 = f"{AESManager.bytes_to_base64(nonce_username)}|{AESManager.bytes_to_base64(ciphertext_username)}|{AESManager.bytes_to_base64(tag_username)}"
            self.client_socket.sendall(encrypted_username_b64.encode('utf-8'))

            self.worker = ChatClientWorker(self.client_socket, self.aes_manager)

            if self.chat_widget:
                self.worker.message_received.connect(self.chat_widget.add_message_to_chat)
                self.worker.connection_error.connect(self.chat_widget.add_message_to_chat)
                self.worker.file_received.connect(self.chat_widget.add_file_to_chat)

            self.thread = threading.Thread(target=self.worker.listen_for_messages, daemon=True)
            self.thread.start()
            print("[INFO] [ChatClient] Thread de escuta iniciada.")
            return True
        except socket.timeout:
            print(f"[ERROR] [ChatClient] Timeout ao tentar conectar ou durante o handshake com {self.host}:{self.port}.")
            if self.chat_widget:
                self.chat_widget.add_message_to_chat(f"[ERROR] Erro de conexão: O servidor não respondeu a tempo.")
        except ConnectionRefusedError:
            print(f"[ERROR] [ChatClient] Conexão recusada por {self.host}:{self.port}. Verifique se o servidor está ativo e as portas corretas.")
            if self.chat_widget:
                self.chat_widget.add_message_to_chat(f"[ERROR] Erro de conexão: Conexão recusada. O servidor pode estar offline ou inacessível.")
        except ValueError as e:
            print(f"[ERROR] [ChatClient] Erro de formato de dados durante o handshake: {e}")
            if self.chat_widget:
                self.chat_widget.add_message_to_chat(f"[ERROR] Erro de comunicação: Dados inválidos recebidos do servidor.")
        except Exception as e:
            print(f"[CRITICAL] [ChatClient] Erro inesperado ao estabelecer conexão ou handshake: {e}")
            if self.chat_widget:
                self.chat_widget.add_message_to_chat(f"[CRITICAL] Erro fatal ao conectar: {e}. Tente novamente.")

            if self.worker:
                self.worker.disconnected.emit()
            else:
                if self.client_socket:
                    try:
                        self.client_socket.close()
                        print("[INFO] [ChatClient] Socket fechado após falha de conexão.")
                    except Exception as close_e:
                        print(f"[ERROR] [ChatClient] Erro ao fechar socket após falha de conexão: {close_e}")
                if self.chat_widget:
                    self.chat_widget.add_message_to_chat("[ERROR] Conexão falhou antes de iniciar o worker.")
        return False

    def send_message(self, message: str):
        try:
            if not self.client_socket:
                raise Exception("Socket não inicializado. Conecte-se primeiro.")
            if not self.aes_manager:
                raise Exception("Chave AES não estabelecida. Handshake ECC falhou?")

            message_data = {
                "type": "text_message",
                "content": message,
                "hash": hashlib.sha256(message.encode('utf-8')).hexdigest()
            }
            json_message_str = json.dumps(message_data)

            nonce, ciphertext, tag = self.aes_manager.encrypt(json_message_str)
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
                self.thread.join(timeout=self.recive_timeout)
                if self.thread.is_alive():
                    print("[WARNING] [ChatClient] Thread do worker não encerrou em tempo.")
        try:
            if self.client_socket:
                self.client_socket.close()
                print("[INFO] [ChatClient] Socket do cliente principal fechado.")
        except Exception as e:
            print(f"[ERROR] [ChatClient] Erro ao fechar socket do cliente principal: {e}")
        print("[INFO] [ChatClient] Cliente desconectado.")

    def disconnect_from_server(self):
        """
        Método público para iniciar a desconexão do cliente.
        Chama o método interno 'disconnect' e emite o sinal de desconexão.
        """
        print("[INFO] [ChatClient] Solicitando desconexão do servidor...")
        self.disconnect()
        if self.chat_widget:
            if self.worker:
                self.worker.disconnected.emit()
            else:
                pass

    def send_file(self, file_path: str):
        try:
            if not self.client_socket:
                raise Exception("Socket não inicializado. Conecte-se primeiro.")
            if not self.aes_manager:
                raise Exception("Chave AES não estabelecida. Handshake ECC falhou?")

            file_size = os.path.getsize(file_path)
            if file_size > 10 * 1024 * 1024:
                raise ValueError("O arquivo excede o tamanho máximo permitido de 10MB.")

            with open(file_path, 'rb') as file:
                file_content = file.read()

            file_hash = hashlib.sha256(file_content).hexdigest()

            filename = os.path.basename(file_path)
            mime_type, _ = mimetypes.guess_type(file_path)
            if mime_type is None:
                mime_type = "application/octet-stream"

            file_data = {
                "type": "archive",
                "filename": filename,
                "mime_type": mime_type,
                "content": AESManager.bytes_to_base64(file_content), 
                "hash": file_hash,
                "sender_username": self.nome_usuario 
            }

            encrypted_file_data_json = json.dumps(file_data)
            nonce, ciphertext, tag = self.aes_manager.encrypt(encrypted_file_data_json)
            full_encrypted_data = nonce + b'<-->' + ciphertext + b'<-->' + tag
            self.client_socket.sendall(len(full_encrypted_data).to_bytes(4, 'big'))
            self.client_socket.sendall(full_encrypted_data)

            print(f"[INFO] [ChatClient] Arquivo '{filename}' enviado com sucesso.")
            self.chat_widget.add_message_to_chat(f"Você enviou o arquivo: {filename}")
        except ValueError as ve:
            print(f"[ERROR] [ChatClient] Erro de validação ao enviar arquivo: {ve}")
            if self.chat_widget:
                self.chat_widget.add_message_to_chat(f"[ERRO] {ve}")
        except Exception as e:
            print(f"[ERROR] [ChatClient] Erro ao enviar arquivo: {e}")
            if self.chat_widget:
                self.chat_widget.add_message_to_chat(f"[ERRO] Erro ao enviar arquivo: {e}")
            raise


