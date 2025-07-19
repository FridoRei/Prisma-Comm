import traceback
import socket
from PySide6.QtCore import QObject, Signal, Slot
from src.core.chat.globals import clientes_lock, handlers, client_aes_keys, client_aes_keys_lock, connected_users, connected_users_lock, authenticated_ips, authenticated_ips_lock
from src.core.crypto.ecc_manager import ECCManager
from src.core.crypto.aes_manager import AESManager
from cryptography.hazmat.primitives.asymmetric import ed25519
from src.core.network.dos_detector import DoSDetector
from src.core.network.request_limiter import RequestLimiter
import html
import json
import hashlib 

CHAT_MESSAGE_MAX_LENGTH = 600
FILE_MAX_SIZE = 10 * 1024 * 1024

def is_utf8_valid(data: bytes) -> bool:
    try:
        data.decode('utf-8')
        return True
    except UnicodeDecodeError:
        return False

def sanitize_chat_message(message: str) -> str:
    """
    Escapa caracteres HTML especiais para prevenir injeção de conteúdo.
    """
    return html.escape(message)

class ClientHandler(QObject):

    new_message_for_host = Signal(str)
    client_status_for_host = Signal(str)
    user_list_updated = Signal()   
    file_received_from_client = Signal(dict, object, object, object) 

    def __init__(self, client_socket, addr, session_aes_key_bytes: bytes, dos_detector: DoSDetector, host_client_data_receive_timeout: int):
        super().__init__()
        self.client_socket = client_socket
        self.addr = addr
        self.username = f"[{addr[0]}]"
        self._running = True
        self.client_socket.settimeout(host_client_data_receive_timeout)
        self.aes_manager = AESManager(session_aes_key_bytes)
        self.ecc_manager = ECCManager() 
        self.dos_detector = dos_detector
        self.request_limiter = RequestLimiter(max_length=CHAT_MESSAGE_MAX_LENGTH)

    def stop(self):
        self._running = False
        try:
            if self.client_socket:
                self.client_socket.shutdown(socket.SHUT_RDWR)
                self.client_socket.close()
        except OSError as e:
            if e.errno != 107:
                print(f"[ERROR] [ClientHandler] Erro ao fechar socket do cliente {self.username} ({self.addr}): {e}")
        except Exception as e:
            print(f"[CRITICAL] [ClientHandler] Erro inesperado ao fechar socket do cliente {self.username} ({self.addr}): {e}")

    @Slot()
    def run(self):
        with clientes_lock:
            handlers.append(self)

        client_ip = self.addr[0]

        try:
            encrypted_username_bytes = self.client_socket.recv(1024)
            if not encrypted_username_bytes:
                print(f"[WARNING] [ClientHandler] Cliente {self.addr[0]} desconectou antes de enviar o nome de usuário.")
                self.client_socket.close()
                return

            if not is_utf8_valid(encrypted_username_bytes):
                print(f"[WARNING] [ClientHandler] Nome de usuário de {self.addr[0]} não é UTF-8 válido. Encerrando conexão.")
                self.client_socket.close()
                return

            encrypted_username_b64 = encrypted_username_bytes.decode('utf-8').strip()

            parts = encrypted_username_b64.split('|')
            if len(parts) == 3:
                nonce = AESManager.base64_to_bytes(parts[0])
                ciphertext = AESManager.base64_to_bytes(parts[1])
                tag = AESManager.base64_to_bytes(parts[2])

                try:
                    decrypted_json_str = self.aes_manager.decrypt(nonce, ciphertext, tag)
                    username_data = json.loads(decrypted_json_str)

                    msg_type = username_data.get("type")
                    username_content = username_data.get("content")
                    username_hash = username_data.get("hash")

                    if msg_type == "username_init" and username_content and username_hash:
                        calculated_hash = hashlib.sha256(username_content.encode('utf-8')).hexdigest()
                        if calculated_hash != username_hash:
                            raise ValueError("Hash do nome de usuário inválido.")

                        self.username = sanitize_chat_message(username_content)
                        self.new_message_for_host.emit(f"[INFO] Cliente '{self.username}' ({self.addr[0]}) conectado.")
                    else:
                        raise ValueError("Formato de dados de nome de usuário inicial inválido.")

                except (json.JSONDecodeError, ValueError) as e:
                    self.new_message_for_host.emit(f"[ERROR] Erro ao processar nome de usuário de {self.addr[0]}. Conexão encerrada.")
                    print(f"[ERROR] [ClientHandler] ERRO ao descriptografar/processar nome de usuário de {self.addr[0]}: {e}")
                    self.client_socket.close()
                    return
            else:
                print(f"[WARNING] [ClientHandler] Formato de nome de usuário inválido de {self.addr[0]}. Encerrando conexão.")
                self.client_socket.close()
                return

            with connected_users_lock:
                connected_users[self.addr[0]] = {
                    "username": self.username,
                    "handler": self
                }
            self.user_list_updated.emit()

            while self._running:
                try:                   
                    header_bytes = self.client_socket.recv(4, socket.MSG_PEEK)
                    if not header_bytes:
                        print(f"[INFO] [ClientHandler] Cliente {self.username} ({self.addr[0]}) desconectou (recebeu dados vazios).")
                        break

                    try:
                        data_length = int.from_bytes(header_bytes, 'big')                        
                        if data_length > 0 and data_length <= FILE_MAX_SIZE + 4096:
                            self.client_socket.recv(4)
                            self._handle_incoming_file(data_length) 
                            continue
                    except ValueError:                        
                        pass

                    encrypted_message_bytes = self.client_socket.recv(8192)
                    if not encrypted_message_bytes:
                        print(f"[INFO] [ClientHandler] Cliente {self.username} ({self.addr[0]}) desconectou (dados vazios após peek).")
                        break

                    if not is_utf8_valid(encrypted_message_bytes):
                        print(f"[WARNING] [ClientHandler] Mensagem de {self.username} ({self.addr[0]}) não é UTF-8 válida. Descartando.")
                        continue

                    encrypted_message_b64 = encrypted_message_bytes.decode('utf-8')

                    if self.request_limiter.is_request_too_large(encrypted_message_b64.encode('utf-8')):
                        print(f"[WARNING] [ClientHandler] Mensagem de {self.username} ({self.addr[0]}) excedeu o limite de tamanho. Descartando.")
                        continue

                    if self.dos_detector and not self.dos_detector.anti_spam_message(self.addr[0]):
                        print(f"[SPAM] Mensagem descartada de {self.addr[0]}")
                        continue

                    parts = encrypted_message_b64.split('|')
                    if len(parts) == 3:
                        nonce = AESManager.base64_to_bytes(parts[0])
                        ciphertext = AESManager.base64_to_bytes(parts[1])
                        tag = AESManager.base64_to_bytes(parts[2])

                        try:
                            decrypted_json_str = self.aes_manager.decrypt(nonce, ciphertext, tag)
                            message_data = json.loads(decrypted_json_str)

                            msg_type = message_data.get("type")
                            msg_content = message_data.get("content")
                            msg_hash = message_data.get("hash")

                            if msg_type == "text_message" and msg_content and msg_hash:
                                calculated_hash = hashlib.sha256(msg_content.encode('utf-8')).hexdigest()
                                if calculated_hash != msg_hash:
                                    print(f"[ERROR] [ClientHandler] Erro de integridade na mensagem de {self.username}. Hash inválido.")
                                    self.new_message_for_host.emit(f"[ERRO] Falha na integridade da mensagem de {self.username}.")
                                    continue

                                sanitized_message = sanitize_chat_message(msg_content)
                                self.new_message_for_host.emit(f"{self.username}: {sanitized_message}")

                                message_data["sender_username"] = self.username
                                self.broadcast_message(message_data, self.client_socket)
                            else:
                                print(f"[WARNING] [ClientHandler] Formato de mensagem JSON inválido ou tipo desconhecido de {self.username} ({self.addr[0]}): {message_data}")
                                self.new_message_for_host.emit(f"[ERRO] Mensagem recebida em formato inválido de {self.username}.")

                        except (json.JSONDecodeError, ValueError) as e:
                            self.new_message_for_host.emit(f"[ERROR] Erro ao processar mensagem de {self.username} ({self.addr[0]}).")
                            print(f"[ERROR] [ClientHandler] ERRO ao descriptografar/processar mensagem de {self.username} ({self.addr[0]}): {e}. Dados: {encrypted_message_b64[:100]}...")
                    else:
                        self.new_message_for_host.emit(f"[WARNING] Formato de mensagem inválido de {self.username} ({self.addr[0]}).")
                        print(f"[WARNING] [ClientHandler] Formato de mensagem inválido de {self.username} ({self.addr[0]}). Dados: {encrypted_message_b64[:100]}...")

                except socket.timeout:
                    continue
                except ConnectionResetError:
                    print(f"[ERROR] [ClientHandler] Conexão reiniciada por {self.username} ({self.addr[0]}).")
                    self.new_message_for_host.emit(f"[ERROR] Conexão com {self.username} ({self.addr[0]}) foi reiniciada.")
                    break
                except Exception as e:
                    if self._running:
                        print(f"[CRITICAL] [ClientHandler] Erro inesperado com cliente {self.username} ({self.addr[0]}).")
                        self.new_message_for_host.emit(f"[ERROR] Erro inesperado com cliente {self.username} ({self.addr[0]}).")
                    break

        finally:
            with clientes_lock:
                if self in handlers:
                    handlers.remove(self)

            with client_aes_keys_lock:
                if client_ip in client_aes_keys:
                    del client_aes_keys[client_ip]
                    self.client_status_for_host.emit(f"[INFO] Chave AES de sessão de {client_ip} removida.")

            with connected_users_lock:
                if client_ip in connected_users:
                    del connected_users[client_ip]
                    print(f"[INFO] [ClientHandler] Usuário {self.username} ({client_ip}) removido da lista de usuários conectados.")
            self.user_list_updated.emit()

            try:
                self.client_socket.close()
            except Exception as e:
                print(f"[ERROR] [ClientHandler] Erro ao fechar socket no bloco finally para {self.username} ({self.addr[0]}): {e}")
            self.client_status_for_host.emit(f"[INFO] Cliente '{self.username}' ({self.addr[0]}) desconectado.")

    def _handle_incoming_file(self, total_data_length: int):
        try:
            encrypted_full_data = b''
            bytes_received = 0
            while bytes_received < total_data_length:
                chunk = self.client_socket.recv(min(total_data_length - bytes_received, 4096))
                if not chunk:
                    print(f"[WARNING] [ClientHandler] Cliente {self.username} ({self.addr[0]}) desconectou durante o recebimento do arquivo.")
                    return
                encrypted_full_data += chunk
                bytes_received += len(chunk)

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

            if msg_type != "archive" or not all([original_filename, mime_type, file_content_b64, received_hash]):
                raise ValueError("Dados de arquivo incompletos, corrompidos ou tipo inválido.")

            file_content_bytes = AESManager.base64_to_bytes(file_content_b64)

            calculated_hash = hashlib.sha256(file_content_bytes).hexdigest()
            if calculated_hash != received_hash:
                print(f"[ERROR] [ClientHandler] Erro de integridade no arquivo '{original_filename}' de {self.username}. Hash inválido.")
                self.new_message_for_host.emit(f"[ERRO] Falha na integridade do arquivo '{original_filename}' de {self.username}.")
                return

            file_data["sender_username"] = self.username
            self.file_received_from_client.emit(file_data, self.client_socket, self.aes_manager, self.dos_detector)

        except json.JSONDecodeError:
            print(f"[ERROR] [ClientHandler] Erro ao decodificar JSON do arquivo recebido de {self.username} ({self.addr[0]}).")
            self.new_message_for_host.emit(f"[ERRO] Erro ao receber arquivo de {self.username}: Dados corrompidos.")
        except Exception as e:
            print(f"[ERROR] [ClientHandler] Erro ao lidar com arquivo recebido de {self.username} ({self.addr[0]}): {e}")
            self.new_message_for_host.emit(f"[ERRO] Erro ao receber arquivo de {self.username}: {e}")



    def send_to_client(self, message_data: dict): 
        try:
            if self._running and self.aes_manager:
                json_message_str = json.dumps(message_data) 
                nonce, ciphertext, tag = self.aes_manager.encrypt(json_message_str)
                encrypted_data_b64 = f"{AESManager.bytes_to_base64(nonce)}|{AESManager.bytes_to_base64(ciphertext)}|{AESManager.bytes_to_base64(tag)}"
                self.client_socket.sendall(encrypted_data_b64.encode('utf-8'))
            elif not self.aes_manager:
                print(f"[WARNING] [ClientHandler] Não foi possível enviar para {self.username} ({self.addr[0]}): Chave AES não estabelecida.")
            else:
                print(f"[WARNING] [ClientHandler] Tentativa de enviar mensagem para cliente {self.username} ({self.addr[0]}) que não está mais rodando.")
        except BrokenPipeError:
            print(f"[ERROR] [ClientHandler] Conexão quebrada ao tentar enviar para {self.username} ({self.addr[0]}). Cliente pode ter desconectado abruptamente.")
            self.stop()
        except Exception as e:
            print(f"[ERROR] [ClientHandler] Erro ao enviar para {self.username} ({self.addr[0]}): {e}")

    def broadcast_message(self, message_data: dict, sender_socket=None): 
        with clientes_lock:
            current_handlers = handlers.copy()

        if not current_handlers:
            return

        for handler in current_handlers:
            if handler.client_socket != sender_socket and handler._running:
                try:
                    with client_aes_keys_lock:
                        dest_aes_key = client_aes_keys.get(handler.addr[0])

                    if dest_aes_key:
                        dest_aes_manager = AESManager(dest_aes_key)
                        json_message_str = json.dumps(message_data) 
                        nonce, ciphertext, tag = dest_aes_manager.encrypt(json_message_str)
                        encrypted_data_b64 = f"{AESManager.bytes_to_base64(nonce)}|{AESManager.bytes_to_base64(ciphertext)}|{AESManager.bytes_to_base64(tag)}"
                        handler.client_socket.sendall(encrypted_data_b64.encode('utf-8'))
                    else:
                        print(f"[WARNING] [ClientHandler] ERRO: Chave AES não encontrada para {handler.username} ({handler.addr[0]}). Não foi possível fazer broadcast.")
                except BrokenPipeError:
                    print(f"[ERROR] [ClientHandler] Conexão quebrada ao tentar broadcast para {handler.username} ({handler.addr[0]}).")
                    handler.stop()
                except Exception as e:
                    print(f"[ERROR] [ClientHandler] Erro no broadcast criptografado para {handler.username} ({handler.addr[0]}): {e}")

