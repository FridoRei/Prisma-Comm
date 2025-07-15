from PySide6.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QPushButton, QLineEdit, QLabel, QMessageBox, QComboBox
import socket
from src.config.settings import ED25519_CHANNELS
from src.core.auth.token_manager import validar_senha_forte

class JoinOptionDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Juntar-se à Rede")
        self.server_ip = None
        self.use_gateway = False
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)

        btn_use_gateway = QPushButton("Usar Gateway de Rede")
        btn_use_gateway.clicked.connect(self._on_use_gateway)
        layout.addWidget(btn_use_gateway)

        layout.addWidget(QLabel("--- OU ---"))

        ip_input_layout = QHBoxLayout()
        self.ip_entry = QLineEdit()
        self.ip_entry.setPlaceholderText("Insira o IP do servidor (ex: 192.168.1.100)")
        ip_input_layout.addWidget(self.ip_entry)

        btn_enter_ip = QPushButton("Conectar ao IP")
        btn_enter_ip.clicked.connect(self._on_enter_ip)
        ip_input_layout.addWidget(btn_enter_ip)
        
        layout.addLayout(ip_input_layout)

    def _on_use_gateway(self):
        self.use_gateway = True
        self.accept()

    def _on_enter_ip(self):
        ip = self.ip_entry.text().strip()
        if not ip:
            QMessageBox.warning(self, "Erro", "Por favor, insira um endereço IP.")
            return
        try:
            socket.inet_aton(ip)  
            self.server_ip = ip
            self.use_gateway = False
            self.accept()
        except socket.error:
            QMessageBox.warning(self, "Erro", "Endereço IP inválido.")
            return

class PasswordInputDialog(QDialog):
    def __init__(self, parent=None, title="Inserir Senha", message="Por favor, insira a senha do host:"):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.password = None
        self.setup_ui(message)

    def setup_ui(self, message):
        layout = QVBoxLayout(self)

        layout.addWidget(QLabel(message))

        self.password_entry = QLineEdit()
        self.password_entry.setEchoMode(QLineEdit.Password)
        self.password_entry.setPlaceholderText("Senha (mín. 12 caracteres, letras, números, @#$%&ç)")
        layout.addWidget(self.password_entry)

        button_layout = QHBoxLayout()
        btn_ok = QPushButton("OK")
        btn_ok.clicked.connect(self._on_ok)
        button_layout.addWidget(btn_ok)

        btn_cancel = QPushButton("Cancelar")
        btn_cancel.clicked.connect(self.reject)
        button_layout.addWidget(btn_cancel)

        layout.addLayout(button_layout)

    def _on_ok(self):
        password = self.password_entry.text()
        if not validar_senha_forte(password):
            QMessageBox.warning(self, "Senha Inválida", "A senha não atende aos requisitos:\n"
                                                        "- Mínimo de 12 caracteres.\n"
                                                        "- Pelo menos uma letra maiúscula.\n"
                                                        "- Pelo menos uma letra minúscula.\n"
                                                        "- Pelo menos um número.\n"
                                                        "- Pelo menos um dos caracteres especiais: @, #, $, %, &, ç.\n"
                                                        "- Apenas caracteres permitidos.")
            return
        self.password = password
        self.accept()

class Ed25519ChannelSelectionDialog(QDialog):
    def __init__(self, parent=None, available_channels: list = None, key_type: str = "privada"):
        super().__init__(parent)
        self.setWindowTitle(f"Selecionar Canal de Chave Ed25519 ({key_type.capitalize()})")
        self.selected_channel = None
        self.available_channels = available_channels if available_channels is not None else []
        self.key_type = key_type
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)

        layout.addWidget(QLabel(f"Por favor, selecione o canal de chave {self.key_type} Ed25519 a ser usado:"))

        self.channel_combo = QComboBox()
        for channel_name in self.available_channels:
            self.channel_combo.addItem(channel_name.capitalize())
        layout.addWidget(self.channel_combo)

        button_layout = QHBoxLayout()
        btn_ok = QPushButton("OK")
        btn_ok.clicked.connect(self._on_ok)
        button_layout.addWidget(btn_ok)

        btn_cancel = QPushButton("Cancelar")
        btn_cancel.clicked.connect(self.reject)
        button_layout.addWidget(btn_cancel)

        layout.addLayout(button_layout)

    def _on_ok(self):
        self.selected_channel = self.available_channels[self.channel_combo.currentIndex()]
        self.accept()