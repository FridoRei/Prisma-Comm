from PySide6.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QPushButton, QLineEdit, QLabel, QMessageBox
import socket

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
