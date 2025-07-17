from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTextEdit,
    QLineEdit, QPushButton, QLabel, QSizePolicy,
    QScrollArea, QFrame 
)
from PySide6.QtCore import Qt, Signal, Slot 
from src.core.chat.chat_client import ChatClient
from src.core.chat.globals import connected_users, connected_users_lock 
import subprocess

class ChatWidget(QWidget):
    disconnect_client_signal = Signal(str) 
    request_client_disconnect = Signal()
    request_host_shutdown = Signal()

    def __init__(self, client: ChatClient = None, is_host: bool = False, broadcast_func=None):
        super().__init__()

        self.client = client
        self.is_host = is_host
        self.broadcast_func = broadcast_func
        self.server_process = None

        self.setup_ui() 
        if self.is_host:
            self.disconnect_client_signal.connect(self._handle_disconnect_client)
            self.update_user_list() 

    def setup_ui(self):
        main_layout = QHBoxLayout(self) 

        chat_area_container = QWidget()
        chat_area_layout = QVBoxLayout(chat_area_container)
        chat_area_container.setStyleSheet("""
            background-color: #3e3e3f;
            border: 1px solid #666;
            border-radius: 8px;
            padding: 5px;
        """)
        chat_area_container.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        self.textview = QTextEdit()
        self.textview.setReadOnly(True)
        self.textview.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding) 
        self.textview.setStyleSheet("""
            background-color: #2e2e2f;
            border: none;
            color: white;
            padding: 5px;
        """)
        chat_area_layout.addWidget(self.textview)

        input_area_container = QWidget()
        input_area_layout = QHBoxLayout(input_area_container)
        input_area_container.setStyleSheet("""
            background-color: #3e3e3f;
            border: 1px solid #666;
            border-radius: 8px;
            padding: 5px;
        """)

        self.entry = QLineEdit()
        self.entry.setPlaceholderText("Digite sua mensagem...")
        self.entry.setStyleSheet("""
            QLineEdit {
                background-color: #2e2e2f;
                border: none;
                border-radius: 5px;
                color: white;
                padding: 5px;
            }
        """)
        self.entry.returnPressed.connect(self.on_send_clicked)
        input_area_layout.addWidget(self.entry)

        send_button = QPushButton("Enviar")
        send_button.clicked.connect(self.on_send_clicked)
        send_button.setStyleSheet("""
            QPushButton {
                background-color: #555;
                border: none;
                border-radius: 5px;
                color: white;
                padding: 5px 10px;
            }
            QPushButton:hover {
                background-color: #666;
            }
            QPushButton:pressed {
                background-color: #444;
            }
        """)
        input_area_layout.addWidget(send_button)
        if not self.is_host:
            self.disconnect_button = QPushButton("Desconectar")
            self.disconnect_button.setStyleSheet("""
                QPushButton {
                    background-color: #d9534f; 
                    border: none;
                    border-radius: 5px;
                    color: white;
                    padding: 5px 10px;
                }
                QPushButton:hover {
                    background-color: #c9302c;
                }
                QPushButton:pressed {
                    background-color: #444;
                }
            """)
            self.disconnect_button.clicked.connect(self.request_client_disconnect.emit)
            input_area_layout.addWidget(self.disconnect_button)   
        else: 
            self.shutdown_host_button = QPushButton("Encerrar Host")
            self.shutdown_host_button.setStyleSheet("""
                QPushButton {
                    background-color: #d9534f; 
                    border: none;
                    border-radius: 5px;
                    color: white;
                    padding: 5px 10px;
                }
                QPushButton:hover {
                    background-color: #c9302c;
                }
                QPushButton:pressed {
                    background-color: #444;
                }
            """)
            self.shutdown_host_button.clicked.connect(self.request_host_shutdown.emit)
            input_area_layout.addWidget(self.shutdown_host_button)                 
        chat_area_layout.addWidget(input_area_container)
        
        main_layout.addWidget(chat_area_container)

        if self.is_host:
            user_list_widget = QWidget()
            user_list_layout = QVBoxLayout(user_list_widget)
            user_list_widget.setFixedWidth(200) 
            user_list_widget.setStyleSheet("""
                background-color: #3e3e3f;
                border: 1px solid #666;
                border-radius: 8px;
                padding: 5px;
            """)

            user_list_layout.addWidget(QLabel("<b>Usuários Conectados:</b>"))
            
            self.user_scroll_area = QScrollArea()
            self.user_scroll_area.setWidgetResizable(True)
            self.user_scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
            
            self.user_list_container = QWidget()
            self.user_list_layout = QVBoxLayout(self.user_list_container)
            self.user_list_layout.setAlignment(Qt.AlignTop) 
            self.user_list_container.setStyleSheet("background-color: #2e2e2f;") 
            
            self.user_scroll_area.setWidget(self.user_list_container)
            user_list_layout.addWidget(self.user_scroll_area)
            
            main_layout.addWidget(user_list_widget)

    def on_send_clicked(self):
        mensagem = self.entry.text().strip()

        if mensagem:
            self.add_message_to_chat(f"Você: {mensagem}")
            self.entry.clear()
            if self.is_host:
                if self.broadcast_func:
                    self.broadcast_func(mensagem, self)
            else:
                if self.client:
                    try:
                        self.client.send_message(mensagem)
                    except Exception as e:
                        self.add_message_to_chat(f"Erro ao enviar: {str(e)}")
                else:
                    self.add_message_to_chat("Erro: Conexão não disponível")

    def add_message_to_chat(self, mensagem: str):
        """Adiciona uma mensagem à área de chat"""
        self.textview.append(mensagem)

    @Slot()
    def update_user_list(self):
        if not self.is_host:
            return

        for i in reversed(range(self.user_list_layout.count())):
            widget_to_remove = self.user_list_layout.itemAt(i).widget()
            if widget_to_remove:
                widget_to_remove.setParent(None) 
                widget_to_remove.deleteLater() 

        with connected_users_lock:
            users = connected_users.copy() 

        if not users:
            no_users_label = QLabel("Nenhum usuário conectado.")
            no_users_label.setStyleSheet("color: #aaa;")
            self.user_list_layout.addWidget(no_users_label)
            return

        for ip, user_data in users.items():
            username = user_data["username"]
            
            user_frame = QFrame()
            user_frame.setFrameShape(QFrame.StyledPanel)
            user_frame.setFrameShadow(QFrame.Raised)
            user_frame.setStyleSheet("""
                QFrame {
                    background-color: #4e4e4f;
                    border: 1px solid #777;
                    border-radius: 5px;
                    margin-bottom: 5px;
                }
            """)
            user_layout = QVBoxLayout(user_frame)
            user_layout.setContentsMargins(5, 5, 5, 5)

            name_label = QLabel(f"<b>{username}</b>")
            name_label.setStyleSheet("color: white;")
            user_layout.addWidget(name_label)

            ip_label = QLabel(f"({ip})")
            ip_label.setStyleSheet("color: #ccc; font-size: 9pt;")
            user_layout.addWidget(ip_label)

            disconnect_button = QPushButton("Desconectar")
            disconnect_button.setStyleSheet("""
                QPushButton {
                    background-color: #d9534f;
                    border: none;
                    border-radius: 3px;
                    color: white;
                    padding: 3px 5px;
                    font-size: 9pt;
                }
                QPushButton:hover {
                    background-color: #c9302c;
                }
            """)
            disconnect_button.clicked.connect(lambda checked, client_ip=ip: self.disconnect_client_signal.emit(client_ip))
            user_layout.addWidget(disconnect_button)

            self.user_list_layout.addWidget(user_frame)

    @Slot(str)
    def _handle_disconnect_client(self, client_ip: str):
        """
        Slot para lidar com a desconexão de um cliente específico.
        Este método é chamado quando o botão "Desconectar" é clicado.
        """
        with connected_users_lock:
            user_data = connected_users.get(client_ip)
            if user_data:
                handler_to_disconnect = user_data.get("handler")
                if handler_to_disconnect:
                    self.add_message_to_chat(f"[Host] Desconectando {user_data['username']} ({client_ip})...")
                    handler_to_disconnect.stop()
                else:
                    self.add_message_to_chat(f"[Host] Erro: Handler não encontrado para {client_ip}.")
            else:
                self.add_message_to_chat(f"[Host] Erro: Cliente {client_ip} não encontrado na lista de conectados.")

