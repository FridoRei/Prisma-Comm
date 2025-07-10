# src/gui/dialogs.py
from PySide6.QtWidgets import (QDialog, QLabel, QPushButton, QVBoxLayout, QHBoxLayout, QLineEdit, QMessageBox)
from PySide6.QtGui import QFont
from src.core.network.wifi_manager import detectar_interfaces_wifi # Nova importação
from src.config.settings import DEFAULT_HOTSPOT_SSID, DEFAULT_HOTSPOT_PASSWORD # Nova importação

class WifiInterfaceSelectionDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Escolher Interface Wi-Fi")
        self.selected_interface = None
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        interfaces = detectar_interfaces_wifi()

        if not interfaces:
            layout.addWidget(QLabel("Nenhuma interface Wi-Fi encontrada."))
            self.setMinimumWidth(300)
            return

        for iface in interfaces:
            hbox_item = QHBoxLayout()
            item_label = QLabel(iface)
            item_label.setFont(QFont("Arial", 14))

            btn_selecionar = QPushButton("Selecionar")
            btn_selecionar.clicked.connect(lambda checked, i=iface: self.select_interface(i))

            hbox_item.addWidget(item_label)
            hbox_item.addStretch()
            hbox_item.addWidget(btn_selecionar)
            layout.addLayout(hbox_item)

    def select_interface(self, iface):
        self.selected_interface = iface
        self.accept()

class HotspotConfigDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Configurar Hotspot")
        self.ssid = DEFAULT_HOTSPOT_SSID
        self.password = DEFAULT_HOTSPOT_PASSWORD
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)

        layout.addWidget(QLabel("Nome da rede (SSID):"))
        self.ssid_entry = QLineEdit(self.ssid)
        layout.addWidget(self.ssid_entry)

        layout.addWidget(QLabel("Senha:"))
        self.senha_entry = QLineEdit(self.password)
        self.senha_entry.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.senha_entry)

        btn_criar = QPushButton("Criar Hotspot")
        btn_criar.clicked.connect(self.accept_config)
        layout.addWidget(btn_criar)

    def accept_config(self):
        ssid = self.ssid_entry.text()
        senha = self.senha_entry.text()

        if len(senha) < 8:
            QMessageBox.warning(self, "Erro", "A senha deve ter pelo menos 8 caracteres.")
            return

        self.ssid = ssid
        self.password = senha
        self.accept()

