import socket
from PySide6.QtCore import QObject, Signal, Slot
from src.core.chat.globals import clientes_lock, handlers 

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

    def stop(self): 
        self._running = False

    @Slot()
    def run(self): 
        with clientes_lock:
            handlers.append(self)
            self.client_status_for_host.emit(f"[Servidor] Cliente conectado: {self.addr}") 

        try:
            try:
                initial_message_bytes = self.client_socket.recv(1024)
                if initial_message_bytes:
                    initial_message = initial_message_bytes.decode('utf-8').strip() 
                    if initial_message.startswith("__USERNAME__:"):
                        self.username = initial_message.split(":", 1)[1]
                        self.client_status_for_host.emit(f"[Servidor] Cliente '{self.username}' ({self.addr}) conectado.")
                    else:
                        print(f"[Servidor] Primeira mensagem inesperada de {self.addr}: {initial_message}")
                        self.new_message_for_host.emit(f"[Servidor] Mensagem inesperada de {self.addr}: {initial_message}")
                else:
                    print(f"[Servidor] Cliente {self.addr} desconectou antes de enviar o nome.")
                    return
            except socket.timeout: 
                print(f"[Servidor] Timeout ao esperar nome de usuário de {self.addr}. Usando IP.")
            except Exception as e:
                print(f"[Servidor] Erro ao receber nome de usuário de {self.addr}: {e}. Usando IP.")

            while self._running: 
                try:
                    mensagem_bytes = self.client_socket.recv(1024) 
                    if not mensagem_bytes: 
                        print(f"[Servidor] Cliente {self.username} ({self.addr}) desconectou")
                        break

                    mensagem = mensagem_bytes.decode('utf-8').strip()
                    self.new_message_for_host.emit(f"{self.username}: {mensagem}")
                    self.broadcast_message(f"{self.username}: {mensagem}", self.client_socket)

                except socket.timeout:
                    continue  
                except Exception as e:
                    if self._running:
                        print(f"[Servidor] Erro com cliente {self.username} ({self.addr}): {e}")
                        self.new_message_for_host.emit(f"[Servidor] Erro com cliente {self.username} ({self.addr}): {e}")
                    break

        finally: 
            with clientes_lock:
                if self in handlers:
                    handlers.remove(self) 
                    print(f"[Servidor] Handler removido para {self.username} ({self.addr})")

            self.client_socket.close()
            self.client_status_for_host.emit(f"[Servidor] Cliente '{self.username}' desconectado.")
            print(f"[Servidor] Conexão encerrada com {self.username} ({self.addr})")

    def send_to_client(self, message: str): 
        try:
            if self._running:
                self.client_socket.sendall(message.encode('utf-8'))
        except Exception as e:
            print(f"[Servidor] Erro ao enviar para {self.username} ({self.addr}): {e}")

    def broadcast_message(self, message: str, sender_socket=None): 
        message_bytes = message.encode('utf-8')

        with clientes_lock:
            current_handlers = handlers.copy()

        for handler in current_handlers:
            if handler.client_socket != sender_socket and handler._running:
                try:
                    handler.client_socket.sendall(message_bytes)
                except Exception as e:
                    print(f"[Servidor] Erro no broadcast para {handler.username} ({handler.addr}): {e}")

