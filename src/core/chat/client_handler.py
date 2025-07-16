import traceback
import socket
from PySide6.QtCore import QObject, Signal, Slot
from src.core.chat.globals import clientes_lock, handlers, authenticated_ips, authenticated_ips_lock, client_aes_keys, client_aes_keys_lock, connected_users, connected_users_lock
from src.core.crypto.ecc_manager import ECCManager
from src.core.crypto.aes_manager import AESManager 
from cryptography.hazmat.primitives.asymmetric import ed25519
from src.core.network.dos_detector import DoSDetector

class ClientHandler(QObject): 

    new_message_for_host = Signal(str)
    client_status_for_host = Signal(str)
    user_list_updated = Signal()

    def __init__(self, client_socket, addr, host_ed25519_private_key: ed25519.Ed25519PrivateKey, dos_detector: DoSDetector):
        super().__init__()
        self.client_socket = client_socket
        self.addr = addr
        self.username = f"[{addr[0]}]" 
        self._running = True
        self.client_socket.settimeout(5.0) 
        self.aes_manager = None 
        self.ecc_manager = ECCManager() 
        self.dos_detector = dos_detector
        
        if host_ed25519_private_key:
            self.ecc_manager._ed25519_private_key = host_ed25519_private_key
            self.ecc_manager._ed25519_public_key = host_ed25519_private_key.public_key()
            print(f"[DEBUG] [ClientHandler] Chave privada Ed25519 do host carregada para {self.addr[0]}.")
        else:
            print(f"[ERROR] [ClientHandler] Nenhuma chave Ed25519 do host fornecida para {self.addr[0]}. Handshake ECC pode falhar.")

        self.host_ed25519_private_key = host_ed25519_private_key

    def stop(self): 
        self._running = False
        try:
            if self.client_socket:
                self.client_socket.shutdown(socket.SHUT_RDWR)
                self.client_socket.close()
                print(f"[INFO] [ClientHandler] Socket do cliente {self.username} ({self.addr}) fechado.")
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
            self.client_status_for_host.emit(f"[INFO] Iniciando handshake de chave ECC com {self.addr[0]}...")
            print(f"[INFO] [ClientHandler] Iniciando handshake de chave ECC com {self.addr[0]}...")
            try:
                self.ecc_manager.generate_x25519_keys()
                server_x25519_public_bytes = self.ecc_manager.get_x25519_public_key_bytes()

                if not self.ecc_manager.has_ed25519_private_key():
                    raise Exception("Chave privada Ed25519 do host não carregada para assinar a chave X25519. Handshake ECC não pode ser seguro.")
                
                signature = self.ecc_manager.sign_data(server_x25519_public_bytes)
                print(f"[DEBUG] [ClientHandler] Chave X25519 do servidor assinada.")

                handshake_data = f"{ECCManager.bytes_to_base64(server_x25519_public_bytes)}|{AESManager.bytes_to_base64(signature)}"
                self.client_socket.sendall(handshake_data.encode('utf-8'))
                self.client_status_for_host.emit(f"[INFO] Chave X25519 e assinatura do servidor enviadas para {self.addr[0]}.")
                print(f"[INFO] [ClientHandler] Chave X25519 e assinatura do servidor enviadas para {self.addr[0]}.")

                client_handshake_response_b64 = self.client_socket.recv(2048).decode('utf-8').strip()
                client_x25519_public_b64 = client_handshake_response_b64

                if not client_x25519_public_b64:
                    raise ValueError("Chave pública X25519 do cliente não recebida ou vazia.")

                client_x25519_public_bytes = ECCManager.base64_to_bytes(client_x25519_public_b64)
                self.client_status_for_host.emit(f"[INFO] Chave X25519 do cliente recebida de {self.addr[0]}.")
                print(f"[INFO] [ClientHandler] Chave X25519 do cliente recebida de {self.addr[0]}.")

                derived_aes_key = self.ecc_manager.derive_shared_key(client_x25519_public_bytes)
                self.aes_manager = AESManager(derived_aes_key)
                self.client_status_for_host.emit(f"[INFO] Chave AES derivada para {self.addr[0]}.")
                print(f"[INFO] [ClientHandler] Chave AES derivada para {self.addr[0]}.")

                with client_aes_keys_lock:
                    client_aes_keys[self.addr[0]] = self.aes_manager.get_key()
                    print(f"[DEBUG] [ClientHandler] Chave AES armazenada para {self.addr[0]}.")

                self.ecc_manager.clear_x25519_keys() 
                print(f"[DEBUG] [ClientHandler] Chaves X25519 efêmeras limpas.")

                self.client_socket.sendall(b"ECC_HANDSHAKE_SUCCESS")
                self.client_status_for_host.emit(f"[SUCCESS] Handshake ECC concluído com {self.addr[0]}.")
                print(f"[SUCCESS] [ClientHandler] Handshake ECC concluído com {self.addr[0]}.")

            except socket.timeout:
                self.client_status_for_host.emit(f"[ERROR] Timeout durante o handshake ECC com {self.addr[0]}.")
                print(f"[ERROR] [ClientHandler] Timeout durante o handshake ECC com {self.addr[0]}.")
                self.client_socket.sendall(b"ECC_HANDSHAKE_FAILURE")
                self.client_socket.close()
                return
            except ValueError as e:
                self.client_status_for_host.emit(f"[ERROR] Erro de formato de dados durante o handshake ECC com {self.addr[0]}.")
                print(f"[ERROR] [ClientHandler] Erro de formato de dados durante o handshake ECC com {self.addr[0]}: {e}")
                self.client_socket.sendall(b"ECC_HANDSHAKE_FAILURE")
                self.client_socket.close()
                return
            except Exception as e:
                self.client_status_for_host.emit(f"[ERROR] Falha no handshake ECC com {self.addr[0]}.")
                print(f"[ERROR] [ClientHandler] Falha no handshake ECC com {self.addr[0]}: {e}")
                self.client_socket.sendall(b"ECC_HANDSHAKE_FAILURE")
                self.client_socket.close()
                return 

            try:
                encrypted_username_b64 = self.client_socket.recv(1024).decode('utf-8').strip()
                if encrypted_username_b64:
                    parts = encrypted_username_b64.split('|')
                    if len(parts) == 3:
                        nonce = AESManager.base64_to_bytes(parts[0])
                        ciphertext = AESManager.base64_to_bytes(parts[1])
                        tag = AESManager.base64_to_bytes(parts[2])
                        
                        try: 
                            decrypted_username = self.aes_manager.decrypt(nonce, ciphertext, tag)
                            self.username = decrypted_username
                            self.client_status_for_host.emit(f"[INFO] Cliente '{self.username}' ({self.addr[0]}) conectado.")
                            print(f"[INFO] [ClientHandler] Cliente '{self.username}' ({self.addr[0]}) conectado.")
                        except Exception as e:
                            self.client_status_for_host.emit(f"[ERROR] Erro ao descriptografar nome de usuário de {self.addr[0]}. Conexão encerrada.")
                            print(f"[ERROR] [ClientHandler] ERRO ao descriptografar nome de usuário de {self.addr[0]}: {e}")
                            self.client_socket.close()
                            return
                else:
                    print(f"[WARNING] [ClientHandler] Cliente {self.addr[0]} desconectou antes de enviar o nome de usuário.")
                    self.client_socket.close()
                    return
                
                with connected_users_lock:
                    connected_users[self.addr[0]] = {
                        "username": self.username,
                        "handler": self
                    }
                self.user_list_updated.emit()                
                print(f"[INFO] [ClientHandler] Usuário {self.username} adicionado à lista de conectados.")
                
            except socket.timeout: 
                print(f"[WARNING] [ClientHandler] Timeout ao esperar nome de usuário de {self.addr[0]}. Cliente desconectado.")
                self.client_socket.close()
                return
            except Exception as e:
                print(f"[ERROR] [ClientHandler] Erro ao receber nome de usuário de {self.addr[0]}: {e}. Cliente desconectado.")
                self.client_socket.close()
                return

            while self._running: 
                try:
                    encrypted_message_b64 = self.client_socket.recv(2048).decode('utf-8') 
                    if not encrypted_message_b64: 
                        print(f"[INFO] [ClientHandler] Cliente {self.username} ({self.addr[0]}) desconectou (recebeu dados vazios).")
                        break

                    if not self.dos_detector.check_and_record(client_ip):
                        print(f"[WARNING] [ClientHandler] Mensagem de {self.username} ({self.addr[0]}) bloqueada por DoSDetector.")
                        continue 

                    parts = encrypted_message_b64.split('|')
                    if len(parts) == 3:
                        nonce = AESManager.base64_to_bytes(parts[0])
                        ciphertext = AESManager.base64_to_bytes(parts[1])
                        tag = AESManager.base64_to_bytes(parts[2])

                        try:
                            mensagem_descriptografada = self.aes_manager.decrypt(nonce, ciphertext, tag)
                            self.new_message_for_host.emit(f"{self.username}: {mensagem_descriptografada}")
                            print(f"[DEBUG] [ClientHandler] Mensagem de {self.username} recebida e descriptografada: {mensagem_descriptografada[:50]}...")
                            self.broadcast_message(f"{self.username}: {mensagem_descriptografada}", self.client_socket)
                        except Exception as e:
                            self.new_message_for_host.emit(f"[ERROR] Erro ao descriptografar mensagem de {self.username} ({self.addr[0]}).")
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
                except UnicodeDecodeError:
                    print(f"[ERROR] [ClientHandler] Erro de decodificação Unicode na mensagem de {self.username} ({self.addr[0]}).")
                    self.new_message_for_host.emit(f"[ERROR] Erro de decodificação na mensagem de {self.username} ({self.addr[0]}).")
                    break
                except Exception as e:
                    if self._running: 
                        print(f"[CRITICAL] [ClientHandler] Erro inesperado com cliente {self.username} ({self.addr[0]}): {e}")
                        self.new_message_for_host.emit(f"[ERROR] Erro inesperado com cliente {self.username} ({self.addr[0]}).")
                    break

        finally: 
            with clientes_lock:
                if self in handlers:
                    handlers.remove(self) 
                    print(f"[INFO] [ClientHandler] Handler para {self.username} ({self.addr[0]}) removido da lista global.")
                    
            with authenticated_ips_lock:
                if client_ip in authenticated_ips:
                    authenticated_ips.remove(client_ip)
                    print(f"[INFO] [ClientHandler] IP {client_ip} removido da lista de IPs autenticados.")
            
            with client_aes_keys_lock: 
                if client_ip in client_aes_keys:
                    del client_aes_keys[client_ip]
                    self.client_status_for_host.emit(f"[INFO] Chave AES de {client_ip} removida.")
                    print(f"[INFO] [ClientHandler] Chave AES de {client_ip} removida.")
                    
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
            print(f"[INFO] [ClientHandler] Cliente '{self.username}' ({self.addr[0]}) desconectado. Thread encerrada.")

    def send_to_client(self, message: str): 
        try:
            if self._running and self.aes_manager:
                nonce, ciphertext, tag = self.aes_manager.encrypt(message)
                encrypted_data_b64 = f"{AESManager.bytes_to_base64(nonce)}|{AESManager.bytes_to_base64(ciphertext)}|{AESManager.bytes_to_base64(tag)}"
                self.client_socket.sendall(encrypted_data_b64.encode('utf-8'))
                print(f"[DEBUG] [ClientHandler] Mensagem enviada para {self.username} ({self.addr[0]}): {message[:50]}...")
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
            print("[INFO] [ClientHandler] Nenhum outro cliente para broadcast.")
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
                        print(f"[DEBUG] [ClientHandler] Mensagem broadcast criptografada para {handler.username} ({handler.addr[0]}): {message[:50]}...")
                    else:
                        print(f"[WARNING] [ClientHandler] ERRO: Chave AES não encontrada para {handler.username} ({handler.addr[0]}). Não foi possível fazer broadcast.")
                except BrokenPipeError:
                    print(f"[ERROR] [ClientHandler] Conexão quebrada ao tentar broadcast para {handler.username} ({handler.addr[0]}).")
                    handler.stop() 
                except Exception as e:
                    print(f"[ERROR] [ClientHandler] Erro no broadcast criptografado para {handler.username} ({handler.addr[0]}): {e}")
