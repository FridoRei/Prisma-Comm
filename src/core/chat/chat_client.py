import socket
import threading
from PySide6.QtCore import QObject, Signal, Slot
from src.core.network.connection_manager import obter_gateway

class ChatClientWorker(QObject):
    message_received = Signal(str)
    connection_error = Signal(str)
    disconnected = Signal()

    def __init__(self, client_socket):
        super().__init__()
        self.client_socket = client_socket
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
                message = self.client_socket.recv(1024).decode()
                if message:
                    if message == "AUTH_REQUIRED": # Adicionar tratamento para AUTH_REQUIRED
                        self.connection_error.emit("[CLIENT] Conexão recusada: Autenticação necessária. Por favor, autentique-se primeiro.")
                        self.disconnected.emit()
                        break
                    self.message_received.emit(message)
                else:
                    self.message_received.emit("[CLIENT] Conexão perdida.")
                    self.disconnected.emit()
                    break
            except Exception as e:
                if self._running:
                    self.connection_error.emit(f"[CLIENT] Erro de conexão: {e}")
                self.disconnected.emit()
                break

        self.client_socket.close()
        print("[CLIENT] Thread de escuta encerrada.")


class ChatClient:
    def __init__(self, port, chat_widget=None, nome_usuario="Usuário"):
        self.host = obter_gateway()
        self.port = port
        self.chat_widget = chat_widget
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.nome_usuario = nome_usuario
        self.worker = None
        self.thread = None

    def connect(self):
        if not self.host:
            print("[CLIENT] Gateway não encontrado, verifique sua rede.")
            return

        try:
            self.client_socket.connect((self.host, self.port))
            print(f"[CLIENT] Conectado ao servidor em {self.host}:{self.port}")

            # Envia o nome de usuário APÓS a conexão ser estabelecida,
            # mas antes de iniciar o worker de escuta, para que o servidor
            # possa identificar o cliente.
            self.client_socket.sendall(f"__USERNAME__:{self.nome_usuario}\n".encode())

            self.worker = ChatClientWorker(self.client_socket)
            self.thread = threading.Thread(target=self.worker.listen_for_messages, daemon=True)

            self.thread.start()
        except Exception as e:
            print(f"[CLIENT] Erro ao estabelecer conexão: {e}")
            if self.chat_widget:
                self.chat_widget.add_message_to_chat(f"[CLIENT] Erro ao conectar: {e}")

            if self.worker:
                self.worker.disconnected.emit()
            else:
                pass

    def send_message(self, message):
        try:
            if not self.client_socket:
                raise Exception("[CLIENT] Socket não inicializado.")

            self.client_socket.sendall((message + "\n").encode())
        except Exception as e:
            print(f"[CLIENT] Erro ao enviar mensagem: {e}")
            if self.chat_widget:
                self.chat_widget.add_message_to_chat(f"[CLIENT] Erro ao enviar: {e}")
            raise

    def disconnect(self):
        if self.worker:
            self.worker.stop()
        print("[CLIENT] Cliente desconectado.")
