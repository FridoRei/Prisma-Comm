import traceback
import socket
from PySide6.QtCore import QObject, Signal, Slot
from src.core.chat.globals import clientes_lock, handlers, authenticated_ips, authenticated_ips_lock, client_aes_keys, client_aes_keys_lock
from src.core.auth.rsa_manager import RSAManager
from src.core.crypto.aes_manager import AESManager 

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
        self.aes_manager = None # A chave AES para este cliente
        self.rsa_manager_temp = RSAManager() # Instância temporária para o handshake RSA

    def stop(self): 
        self._running = False

    @Slot()
    def run(self): 
        with clientes_lock:
            handlers.append(self) 
        try:
            # --- PASSO 1: Handshake de Chave AES (RSA para AES) ---
            self.client_status_for_host.emit(f"[ClientHandler] Iniciando handshake de chave AES com {self.addr[0]}...")
            try:
                # 1. Servidor gera par RSA temporário e envia chave pública
                self.rsa_manager_temp.generate_temp_keys()
                public_key_bytes = self.rsa_manager_temp.get_public_key_bytes()
                self.client_socket.sendall(public_key_bytes)
                self.client_status_for_host.emit(f"[ClientHandler] Chave pública RSA enviada para {self.addr[0]}.")
            
                # 2. Servidor recebe chave AES criptografada do cliente
                encrypted_aes_key_b64 = self.client_socket.recv(2048).decode('utf-8')               
                encrypted_aes_key = AESManager.base64_to_bytes(encrypted_aes_key_b64)
                self.client_status_for_host.emit(f"[ClientHandler] Chave AES criptografada recebida de {self.addr[0]}.")

                # 3. Servidor descriptografa a chave AES
                aes_key_bytes = self.rsa_manager_temp.decrypt_bytes(encrypted_aes_key)
                self.aes_manager = AESManager(aes_key_bytes)
                self.client_status_for_host.emit(f"[ClientHandler] Chave AES descriptografada para {self.addr[0]}.")

                # 4. Servidor armazena a chave AES e descarta o par RSA temporário
                with client_aes_keys_lock:
                    client_aes_keys[self.addr[0]] = self.aes_manager.get_key()
                self.rsa_manager_temp.clear_keys() # Descarta as chaves RSA temporárias
                self.client_socket.sendall(b"AES_HANDSHAKE_SUCCESS")
                self.client_status_for_host.emit(f"[ClientHandler] Handshake AES concluído com {self.addr[0]}.")

            except Exception as e:
                self.client_status_for_host.emit(f"[ClientHandler] ERRO no handshake AES com {self.addr[0]}: {e}")
                print(f"[ClientHandler DEBUG] ERRO DETALHADO: {e}")
                traceback.print_exc()
                self.client_socket.sendall(b"AES_HANDSHAKE_FAILURE")
                self.client_socket.close()
                return # Aborta a conexão se o handshake falhar

            # --- Lógica de recebimento de nome de usuário (mantida) ---
            try:
                initial_message_bytes = self.client_socket.recv(1024)
                if initial_message_bytes:
                    initial_message = initial_message_bytes.decode('utf-8').strip() 
                    if initial_message.startswith("__USERNAME__:"):
                        self.username = initial_message.split(":", 1)[1]
                        self.client_status_for_host.emit(f"[ClientHandler] Cliente '{self.username}' conectado.")
                    else:
                        print(f"[ClientHandler] Primeira mensagem inesperada de {self.addr}: {initial_message}")
                        self.new_message_for_host.emit(f"[ClientHandler] Mensagem inesperada de {self.addr}: {initial_message}")
                else:
                    print(f"[ClientHandler] Cliente {self.addr} desconectou antes de enviar o nome.")
                    return
            except socket.timeout: 
                print(f"[ClientHandler] Timeout ao esperar nome de usuário de {self.addr}. Usando IP.")
            except Exception as e:
                print(f"[ClientHandler] Erro ao receber nome de usuário de {self.addr}: {e}. Usando IP.")

            # --- Loop principal de mensagens (agora com criptografia) ---
            while self._running: 
                try:
                    # Recebe a mensagem criptografada (nonce + ciphertext + tag)
                    # Assumimos um formato: nonce_b64|ciphertext_b64|tag_b64
                    encrypted_message_b64 = self.client_socket.recv(2048).decode('utf-8') # Aumentar buffer se necessário
                    if not encrypted_message_b64: 
                        print(f"[ClientHandler] Cliente {self.username} ({self.addr}) desconectou")
                        break

                    parts = encrypted_message_b64.split('|')
                    if len(parts) == 3:
                        nonce = AESManager.base64_to_bytes(parts[0])
                        ciphertext = AESManager.base64_to_bytes(parts[1])
                        tag = AESManager.base64_to_bytes(parts[2])

                        # Descriptografa a mensagem
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
            
            with client_aes_keys_lock: # Remover a chave AES do cliente ao desconectar
                if client_ip in client_aes_keys:
                    del client_aes_keys[client_ip]
                    self.client_status_for_host.emit(f"[ClientHandler] Chave AES de {client_ip} removida.")

            self.client_socket.close()
            self.client_status_for_host.emit(f"[ClientHandler] Cliente '{self.username}' desconectado.")

    def send_to_client(self, message: str): 
        try:
            if self._running and self.aes_manager: # Só envia se estiver rodando e tiver chave AES
                # Criptografa a mensagem com a chave AES DESTE CLIENTE
                nonce, ciphertext, tag = self.aes_manager.encrypt(message)
                # Envia no formato nonce_b64|ciphertext_b64|tag_b64
                encrypted_data_b64 = f"{AESManager.bytes_to_base64(nonce)}|{AESManager.bytes_to_base64(ciphertext)}|{AESManager.bytes_to_base64(tag)}"
                self.client_socket.sendall(encrypted_data_b64.encode('utf-8'))
            elif not self.aes_manager:
                print(f"[ClientHandler] Não foi possível enviar para {self.username} ({self.addr}): Chave AES não estabelecida.")
        except Exception as e:
            print(f"[ClientHandler] Erro ao enviar para {self.username} ({self.addr}): {e}")

    def broadcast_message(self, message: str, sender_socket=None): 
        # A mensagem 'message' aqui JÁ ESTÁ DESCRIPTOGRAFADA pelo remetente.
        # Agora, precisamos criptografá-la para CADA DESTINATÁRIO com a chave DELE.
        with clientes_lock:
            current_handlers = handlers.copy()

        for handler in current_handlers:
            # Não envia para o próprio remetente e verifica se o handler está ativo
            if handler.client_socket != sender_socket and handler._running:
                try:
                    # Obtém a chave AES do destinatário
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

