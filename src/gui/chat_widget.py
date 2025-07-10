from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTextEdit,
    QLineEdit, QPushButton, QCheckBox, QLabel, QTabWidget, QSizePolicy
)
from PySide6.QtCore import Qt
from src.core.chat.chat_client import ChatClient 
import subprocess

class ChatWidget(QWidget): 
    def __init__(self, client: ChatClient = None, is_host: bool = False, broadcast_func=None):
        super().__init__()

        self.client = client  
        self.is_host = is_host  
        self.broadcast_func = broadcast_func  
        self.server_process = None  

        layout = QVBoxLayout(self)  

        self.tabs = QTabWidget(self)  
        layout.addWidget(self.tabs)  

        self.chat_widget = QWidget()  
        self.chat_layout = QVBoxLayout(self.chat_widget)  

        message_area_container = QWidget()  
        message_area_container_layout = QVBoxLayout(message_area_container)  
        message_area_container.setStyleSheet("""
            background-color: #3e3e3f; /* Cor de fundo do retângulo */
            border: 1px solid #666; /* Borda */
            border-radius: 8px; /* Bordas arredondadas */
            padding: 5px; /* Espaçamento interno */
        """)

        self.textview = QTextEdit()  
        self.textview.setReadOnly(True)  
        self.textview.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)  
        self.textview.setStyleSheet("""
            background-color: #2e2e2f; /* Cor de fundo do textview */
            border: none; /* Remove borda padrão */
            color: white; /* Cor do texto */
            padding: 5px; /* Espaçamento interno */
        """)
        message_area_container_layout.addWidget(self.textview)  
        self.chat_layout.addWidget(message_area_container)  

        self.chat_layout.addSpacing(10)  

        input_area_container = QWidget() 
        input_area_container_layout = QHBoxLayout(input_area_container)  
        input_area_container.setStyleSheet("""
            background-color: #3e3e3f; /* Cor de fundo do retângulo */
            border: 1px solid #666; /* Borda */
            border-radius: 8px; /* Bordas arredondadas */
            padding: 5px; /* Espaçamento interno */
        """)


        self.entry = QLineEdit()  
        self.entry.setPlaceholderText("Digite sua mensagem...")  
        self.entry.setStyleSheet("""
            QLineEdit {
                background-color: #2e2e2f; /* Cor de fundo do input */
                border: none; /* Remove borda padrão */
                border-radius: 5px; /* Bordas arredondadas */
                color: white; /* Cor do texto */
                padding: 5px; /* Espaçamento interno */
            }
        """)
        self.entry.returnPressed.connect(self.on_send_clicked)  
        input_area_container_layout.addWidget(self.entry)  

        send_button = QPushButton("Enviar")  
        send_button.clicked.connect(self.on_send_clicked)  
        send_button.setStyleSheet("""
            QPushButton {
                background-color: #555; /* Cor de fundo do botão */
                border: none; /* Remove borda padrão */
                border-radius: 5px; /* Bordas arredondadas */
                color: white; /* Cor do texto */
                padding: 5px 10px; /* Espaçamento interno */
            }
            QPushButton:hover {
                background-color: #666; /* Cor de fundo ao passar o mouse */
            }
            QPushButton:pressed {
                background-color: #444; /* Cor de fundo ao pressionar */
            }
        """)
        input_area_container_layout.addWidget(send_button) 

        self.chat_layout.addWidget(input_area_container)  
        
        self.tabs.addTab(self.chat_widget, "Chat")  

        if self.is_host:  
            self.settings_widget = QWidget()  
            self.settings_layout = QVBoxLayout(self.settings_widget)  

            settings_label = QLabel("Configurações do Chat (Host):") 
            settings_label.setStyleSheet("color: white;")  
            self.settings_layout.addWidget(settings_label)  
            self.settings_layout.addStretch()  

            self.tabs.addTab(self.settings_widget, "Configurações")  

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

