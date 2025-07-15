import traceback
import socket
from PySide6.QtCore import QObject, Signal, Slot
from src.core.chat.globals import clientes_lock, handlers, authenticated_ips, authenticated_ips_lock, client_aes_keys, client_aes_keys_lock, connected_users, connected_users_lock
from src.core.crypto.ecc_manager import ECCManager
from src.core.crypto.aes_manager import AESManager 
from cryptography.hazmat.primitives.asymmetric import ed25519

class ClientHandler(QObject): 

    new_message_for_host = Signal(str)
    client_status_for_host = Signal(str)
    user_list_updated = Signal()

    def __init__(self, client_socket, addr, host_ed25519_private_key: ed25519.Ed25519PrivateKey, host_ed25519_public_key_bytes: bytes): 
        super().__init__()
        self.client_socket = client_socket
        self.addr = addr
        self.username = f"[{addr[0]}]"
        self._running = True
        self.client_socket.settimeout(1.0)
        self.aes_manager = None 
        self.ecc_manager = ECCManager() 
        
        if host_ed25519_private_key:
            self.ecc_manager._ed25519_private_key = host_ed25519_private_key
            self.ecc_manager._ed25519_public_key = host_ed25519_private_key.public_key()
        elif host_ed25519_public_key_bytes:
            self.ecc_manager.load_ed25519_public_key(host_ed25519_public_key_bytes) 
                  
        self.host_ed25519_private_key = host_ed25519_private_key 
        self.host_ed25519_public_key_bytes = host_ed25519_public_key_bytes

    def stop(self): 
        self._running = False
        try:
            if self.client_socket:
                self.client_socket.shutdown(socket.SHUT_RDWR)
                self.client_socket.close()
        except Exception as e:
            print(f"[ClientHandler] Erro ao fechar socket do cliente {self.username}: {e}")        

    @Slot()
    def run(self): 
        with clientes_lock:
            handlers.append(self) 
        try:
            self.client_status_for_host.emit(f"[ClientHandler] Iniciando handshake de chave ECC com {self.addr[0]}...")
            try:
                self.ecc_manager.generate_x25519_keys()
                server_x25519_public_bytes = self.ecc_manager.get_x25519_public_key_bytes()
                
                signature = self.ecc_manager.sign_data(server_x25519_public_bytes)

                handshake_data = f"{ECCManager.bytes_to_base64(server_x25519_public_bytes)}|{ECCManager.bytes_to_base64(signature)}|{ECCManager.bytes_to_base64(self.host_ed25519_public_key_bytes)}"
                self.client_socket.sendall(handshake_data.encode('utf-8'))
                self.client_status_for_host.emit(f"[ClientHandler] Chaves X25519 e Ed25519 do servidor enviadas para {self.addr[0]}.")

                client_handshake_response_b64 = self.client_socket.recv(2048).decode('utf-8')
                parts = client_handshake_response_b64.split('|')
                if len(parts) != 3:
                    raise ValueError("Formato de handshake do cliente inválido.")
                
                client_x25519_public_b64 = parts[0]
                client_signature_b64 = parts[1]
                client_ed25519_public_b64 = parts[2] 

                client_x25519_public_bytes = ECCManager.base64_to_bytes(client_x25519_public_b64)
                client_signature_bytes = ECCManager.base64_to_bytes(client_signature_b64)
                client_ed25519_public_bytes = ECCManager.base64_to_bytes(client_ed25519_public_b64)

                self.client_status_for_host.emit(f"[ClientHandler] Chaves X25519 e Ed25519 do cliente recebidas de {self.addr[0]}.")

                if not ECCManager.verify_signature(client_ed25519_public_bytes, client_x25519_public_bytes, client_signature_bytes):
                    raise Exception("Falha na verificação da assinatura da chave X25519 do cliente.")
                self.client_status_for_host.emit(f"[ClientHandler] Assinatura da chave X25519 do cliente verificada com sucesso para {self.addr[0]}.")

                derived_aes_key = self.ecc_manager.derive_shared_key(client_x25519_public_bytes)
                self.aes_manager = AESManager(derived_aes_key)
                self.client_status_for_host.emit(f"[ClientHandler] Chave AES derivada para {self.addr[0]}.")

                with client_aes_keys_lock:
                    client_aes_keys[self.addr[0]] = self.aes_manager.get_key()
                
                self.ecc_manager.clear_x25519_keys() 

                self.client_socket.sendall(b"ECC_HANDSHAKE_SUCCESS")
                self.client_status_for_host.emit(f"[ClientHandler] Handshake ECC concluído com {self.addr[0]}.")

            except Exception as e:
                self.client_status_for_host.emit(f"[ClientHandler] ERRO no handshake ECC com {self.addr[0]}: {e}")
                print(f"[ClientHandler DEBUG] ERRO DETALHADO: {e}")
                traceback.print_exc()
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
                            self.client_status_for_host.emit(f"[ClientHandler] Cliente '{self.username}' conectado.")
                        except Exception as e:
                            print(f"[ClientHandler] ERRO ao descriptografar nome de usuário de {self.addr}: {e}")
                            self.client_status_for_host.emit(f"[ClientHandler] ERRO ao descriptografar nome de usuário de {self.addr}: {e}")
                            self.client_socket.close()
                            return
                else:
                    print(f"[ClientHandler] Cliente {self.addr} desconectou antes de enviar o nome.")
                    self.client_socket.close()
                    return
                
                with connected_users_lock:
                    connected_users[self.addr[0]] = {
                        "username": self.username,
                        "handler": self
                    }
                self.user_list_updated.emit()                
                
            except socket.timeout: 
                print(f"[ClientHandler] Timeout ao esperar nome de usuário de {self.addr}. Usando IP.")
                self.client_socket.close()
                return
            except Exception as e:
                print(f"[ClientHandler] Erro ao receber nome de usuário de {self.addr}: {e}. Usando IP.")
                self.client_socket.close()
                return

            while self._running: 
                try:
                    encrypted_message_b64 = self.client_socket.recv(2048).decode('utf-8') 
                    if not encrypted_message_b64: 
                        print(f"[ClientHandler] Cliente {self.username} ({self.addr}) desconectou")
                        break

                    parts = encrypted_message_b64.split('|')
                    if len(parts) == 3:
                        nonce = AESManager.base64_to_bytes(parts[0])
                        ciphertext = AESManager.base64_to_bytes(parts[1])
                        tag = AESManager.base64_to_bytes(parts[2])

                        try:
                            mensagem_descriptografada = self.aes_manager.decrypt(nonce, ciphertext, tag)
                            self.new_message_for_host.emit(f"{self.username}: {mensagem_descriptografada}")
                            self.broadcast_message(f"{self.username}: {mensagem_descriptografada}", self.client_socket)
                        except Exception as e:
                            self.new_message_for_host.emit(f"[ClientHandler] ERRO ao descriptografar mensagem de {self.username} ({self.addr}): {e}")
                            print(f"[ClientHandler] ERRO ao descriptografar mensagem de {self.username} ({self.addr}): {e}")
                    else:
                        self.new_message_for_host.emit(f"[ClientHandler] Formato de mensagem inválido de {self.username} ({self.addr}).")
                        print(f"[ClientHandler] Formato de mensagem inválido de {self.username} ({self.addr}).")

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
                    
            client_ip = self.addr[0]
            with authenticated_ips_lock:
                if client_ip in authenticated_ips:
                    authenticated_ips.remove(client_ip)
            
            with client_aes_keys_lock: 
                if client_ip in client_aes_keys:
                    del client_aes_keys[client_ip]
                    self.client_status_for_host.emit(f"[ClientHandler] Chave AES de {client_ip} removida.")
                    
            with connected_users_lock:
                if client_ip in connected_users:
                    del connected_users[client_ip]
            self.user_list_updated.emit()                    

            self.client_socket.close()
            self.client_status_for_host.emit(f"[ClientHandler] Cliente '{self.username}' desconectado.")

    def send_to_client(self, message: str): 
        try:
            if self._running and self.aes_manager:
                nonce, ciphertext, tag = self.aes_manager.encrypt(message)
                encrypted_data_b64 = f"{AESManager.bytes_to_base64(nonce)}|{AESManager.bytes_to_base64(ciphertext)}|{AESManager.bytes_to_base64(tag)}"
                self.client_socket.sendall(encrypted_data_b64.encode('utf-8'))
            elif not self.aes_manager:
                print(f"[ClientHandler] Não foi possível enviar para {self.username} ({self.addr}): Chave AES não estabelecida.")
        except Exception as e:
            print(f"[ClientHandler] Erro ao enviar para {self.username} ({self.addr}): {e}")

    def broadcast_message(self, message: str, sender_socket=None): 
        with clientes_lock:
            current_handlers = handlers.copy()

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
                        print(f"[ClientHandler] ERRO: Chave AES não encontrada para {handler.username} ({handler.addr}). Não foi possível fazer broadcast.")
                except Exception as e:
                    print(f"[ClientHandler] Erro no broadcast criptografado para {handler.username} ({handler.addr}): {e}")

