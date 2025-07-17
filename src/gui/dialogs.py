from PySide6.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QPushButton, QLineEdit, QLabel, QMessageBox, QComboBox, QFormLayout, QSpinBox
import socket
from src.config.settings import ED25519_CHANNELS, \
    DEFAULT_CLIENT_RSA_TIMEOUT, DEFAULT_CLIENT_PASSWORD_RESPONSE_TIMEOUT, \
    DEFAULT_CLIENT_MESSAGE_RECEIVE_TIMEOUT, DEFAULT_CLIENT_HANDSHAKE_TIMEOUT, \
    DEFAULT_HOST_UDP_OPERATION_TIMEOUT, DEFAULT_HOST_CLIENT_DATA_RECEIVE_TIMEOUT
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
        
class AdvancedTimeoutDialog(QDialog):
    def __init__(self, parent=None, current_timeouts: dict = None):
        super().__init__(parent)
        self.setWindowTitle("Opções Avançadas de Timeout")
        self.setModal(True) # Torna a janela modal

        self.timeouts = current_timeouts if current_timeouts is not None else {}
        self.setup_ui()

    def setup_ui(self):
        main_layout = QVBoxLayout(self)
        form_layout = QFormLayout()

        # 1. (Cliente) Tempo de espera pela chave RSA
        self.client_rsa_timeout_spinbox = QSpinBox()
        self.client_rsa_timeout_spinbox.setRange(0, 30)
        self.client_rsa_timeout_spinbox.setValue(self.timeouts.get("client_rsa_timeout", DEFAULT_CLIENT_RSA_TIMEOUT))
        form_layout.addRow("Tempo de espera pela chave RSA (Cliente):", self.client_rsa_timeout_spinbox)

        # 2. (Cliente) Tempo de espera para resposta à senha
        self.client_password_response_timeout_spinbox = QSpinBox()
        self.client_password_response_timeout_spinbox.setRange(0, 10)
        self.client_password_response_timeout_spinbox.setValue(self.timeouts.get("client_password_response_timeout", DEFAULT_CLIENT_PASSWORD_RESPONSE_TIMEOUT))
        form_layout.addRow("Tempo de espera para resposta à senha (Cliente):", self.client_password_response_timeout_spinbox)

        # 3. (Cliente) Tempo de espera por mensagens
        self.client_message_receive_timeout_spinbox = QSpinBox()
        self.client_message_receive_timeout_spinbox.setRange(0, 10)
        self.client_message_receive_timeout_spinbox.setValue(self.timeouts.get("client_message_receive_timeout", DEFAULT_CLIENT_MESSAGE_RECEIVE_TIMEOUT))
        form_layout.addRow("Tempo de espera por mensagens (Cliente):", self.client_message_receive_timeout_spinbox)

        # 4. (Cliente) Tempo de espera para handshake
        self.client_handshake_timeout_spinbox = QSpinBox()
        self.client_handshake_timeout_spinbox.setRange(0, 20)
        self.client_handshake_timeout_spinbox.setValue(self.timeouts.get("client_handshake_timeout", DEFAULT_CLIENT_HANDSHAKE_TIMEOUT))
        form_layout.addRow("Tempo de espera para handshake (Cliente):", self.client_handshake_timeout_spinbox)

        # 5. (Host) Tempo de operação UDP
        self.host_udp_operation_timeout_spinbox = QSpinBox()
        self.host_udp_operation_timeout_spinbox.setRange(0, 10)
        self.host_udp_operation_timeout_spinbox.setValue(self.timeouts.get("host_udp_operation_timeout", DEFAULT_HOST_UDP_OPERATION_TIMEOUT))
        form_layout.addRow("Tempo de operação UDP (Host):", self.host_udp_operation_timeout_spinbox)

        # 6. (Host) Tempo de espera para receber dados por cliente
        self.host_client_data_receive_timeout_spinbox = QSpinBox()
        self.host_client_data_receive_timeout_spinbox.setRange(0, 30)
        self.host_client_data_receive_timeout_spinbox.setValue(self.timeouts.get("host_client_data_receive_timeout", DEFAULT_HOST_CLIENT_DATA_RECEIVE_TIMEOUT))
        form_layout.addRow("Tempo de espera para receber dados por cliente (Host):", self.host_client_data_receive_timeout_spinbox)

        main_layout.addLayout(form_layout)

        button_layout = QHBoxLayout()
        btn_ok = QPushButton("OK")
        btn_ok.clicked.connect(self._on_ok)
        button_layout.addWidget(btn_ok)

        btn_cancel = QPushButton("Cancelar")
        btn_cancel.clicked.connect(self.reject)
        button_layout.addWidget(btn_cancel)

        main_layout.addLayout(button_layout)

    def _on_ok(self):
        self.timeouts["client_rsa_timeout"] = self.client_rsa_timeout_spinbox.value()
        self.timeouts["client_password_response_timeout"] = self.client_password_response_timeout_spinbox.value()
        self.timeouts["client_message_receive_timeout"] = self.client_message_receive_timeout_spinbox.value()
        self.timeouts["client_handshake_timeout"] = self.client_handshake_timeout_spinbox.value()
        self.timeouts["host_udp_operation_timeout"] = self.host_udp_operation_timeout_spinbox.value()
        self.timeouts["host_client_data_receive_timeout"] = self.host_client_data_receive_timeout_spinbox.value()
        self.accept()

    def get_timeouts(self):
        return self.timeouts        