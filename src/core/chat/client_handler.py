# /wifi-chat v2/src/core/chat/client_handler.py

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
    # O sinal file_received_from_client agora também passa o tamanho total esperado
    file_received_from_client = Signal(str, str, bytes, str, object, object, object, int)

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
                    decrypted_username = self.aes_manager.decrypt(nonce, ciphertext, tag)
                    self.username = sanitize_chat_message(decrypted_username)
                    self.new_message_for_host.emit(f"[INFO] Cliente '{self.username}' ({self.addr[0]}) conectado.")
                except Exception as e:
                    self.new_message_for_host.emit(f"[ERROR] Erro ao processar nome de usuário de {self.addr[0]}. Conexão encerrada.")
                    print(f"[ERROR] [ClientHandler] ERRO ao descriptografar nome de usuário de {self.addr[0]}: {e}")
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
                    # Peek para verificar o tipo de dado (mensagem ou arquivo)
                    header_bytes = self.client_socket.recv(4, socket.MSG_PEEK)
                    if not header_bytes:
                        print(f"[INFO] [ClientHandler] Cliente {self.username} ({self.addr[0]}) desconectou (recebeu dados vazios).")
                        break

                    # Tenta decodificar como int para ver se é um tamanho de arquivo
                    try:
                        data_length = int.from_bytes(header_bytes, 'big')
                        # Se for um número grande, provavelmente é um arquivo
                        if data_length > 0 and data_length <= FILE_MAX_SIZE + 4096: # Max 10MB + overhead
                            # Consome os 4 bytes do tamanho
                            self.client_socket.recv(4)
                            # Emite o sinal para o ChatServer lidar com a transferência do arquivo
                            # Passamos o data_length para que handle_file_transfer saiba quantos bytes esperar
                            self.file_received_from_client.emit(
                                "", "", b"", self.username, self.client_socket, self.aes_manager, self.dos_detector, data_length
                            )
                            # IMPORTANTE: Não tente ler mais dados do socket neste loop,
                            # pois handle_file_transfer irá consumir o restante do arquivo.
                            # A próxima iteração do loop lerá a próxima "mensagem" ou "cabeçalho de arquivo".
                            continue # Pula o restante do loop e vai para a próxima iteração

                    except ValueError:
                        # Não é um tamanho de arquivo, então é uma mensagem de chat normal
                        pass

                    # Se não foi um arquivo, processa como mensagem de chat
                    encrypted_message_bytes = self.client_socket.recv(8192)
                    if not encrypted_message_bytes:
                        print(f"[INFO] [ClientHandler] Cliente {self.username} ({self.addr[0]}) desconectou (dados vazios após peek).")
                        break

                    # A validação UTF-8 só deve ocorrer para mensagens de chat, não para dados binários de arquivo
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
                            mensagem_descriptografada = self.aes_manager.decrypt(nonce, ciphertext, tag)
                            sanitized_message = sanitize_chat_message(mensagem_descriptografada)
                            self.new_message_for_host.emit(f"{self.username}: {sanitized_message}")
                            self.broadcast_message(f"{self.username}: {sanitized_message}", self.client_socket)
                        except Exception as e:
                            self.new_message_for_host.emit(f"[ERROR] Erro ao processar mensagem de {self.username} ({self.addr[0]}).")
                            print(f"[ERROR] [ClientHandler] ERRO ao descriptografar mensagem de {self.username} ({self.addr[0]}): {e}. Dados: {encrypted_message_b64[:100]}...")
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


    def send_to_client(self, message: str):
        try:
            if self._running and self.aes_manager:
                nonce, ciphertext, tag = self.aes_manager.encrypt(message)
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

    def broadcast_message(self, message: str, sender_socket=None):
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
                        nonce, ciphertext, tag = dest_aes_manager.encrypt(message)
                        encrypted_data_b64 = f"{AESManager.bytes_to_base64(nonce)}|{AESManager.bytes_to_base64(ciphertext)}|{AESManager.bytes_to_base64(tag)}"
                        handler.client_socket.sendall(encrypted_data_b64.encode('utf-8'))
                    else:
                        print(f"[WARNING] [ClientHandler] ERRO: Chave AES não encontrada para {handler.username} ({handler.addr[0]}). Não foi possível fazer broadcast.")
                except BrokenPipeError:
                    print(f"[ERROR] [ClientHandler] Conexão quebrada ao tentar broadcast para {handler.username} ({handler.addr[0]}).")
                    handler.stop()
                except Exception as e:
                    print(f"[ERROR] [ClientHandler] Erro no broadcast criptografado para {handler.username} ({handler.addr[0]}): {e}")

