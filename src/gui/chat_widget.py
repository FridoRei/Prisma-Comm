# src/gui/chat_widget.py
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTextEdit,
    QLineEdit, QPushButton, QCheckBox, QLabel, QTabWidget, QSizePolicy
)
from PySide6.QtCore import Qt
from src.core.chat.chat_client import ChatClient # Nova importação
import subprocess

class ChatWidget(QWidget): # Renomeado de ChatWindow para ChatWidget
    def __init__(self, client: ChatClient = None, is_host: bool = False, broadcast_func=None):
        super().__init__()

        self.client = client  # Armazena a instância do cliente de chat
        self.is_host = is_host  # Indica se a instância é do host, habilitando configurações específicas
        self.broadcast_func = broadcast_func  # Função de broadcast, utilizada apenas se for o host
        self.server_process = None  # Referência para o processo do servidor

        layout = QVBoxLayout(self)  # Cria um layout vertical para o widget

        # Criar o QTabWidget para alternar entre as abas
        self.tabs = QTabWidget(self)  # Cria um widget de abas
        layout.addWidget(self.tabs)  # Adiciona o QTabWidget ao layout principal

        # Aba de Chat
        self.chat_widget = QWidget()  # Cria um widget para a aba de chat
        self.chat_layout = QVBoxLayout(self.chat_widget)  # Cria um layout vertical para a aba de chat

        message_area_container = QWidget()  # Cria um contêiner para a área de mensagens
        message_area_container_layout = QVBoxLayout(message_area_container)  # Layout vertical para o contêiner
        message_area_container.setStyleSheet("""
            background-color: #3e3e3f; /* Cor de fundo do retângulo */
            border: 1px solid #666; /* Borda */
            border-radius: 8px; /* Bordas arredondadas */
            padding: 5px; /* Espaçamento interno */
        """)

        # Área de Logs
        self.textview = QTextEdit()  # Cria um QTextEdit para exibir mensagens
        self.textview.setReadOnly(True)  # Define como somente leitura
        self.textview.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)  # Permite que o QTextEdit expanda
        self.textview.setStyleSheet("""
            background-color: #2e2e2f; /* Cor de fundo do textview */
            border: none; /* Remove borda padrão */
            color: white; /* Cor do texto */
            padding: 5px; /* Espaçamento interno */
        """)
        message_area_container_layout.addWidget(self.textview)  # Adiciona a área de mensagens ao contêiner
        self.chat_layout.addWidget(message_area_container)  # Adiciona o contêiner ao layout da aba de chat

        self.chat_layout.addSpacing(10)  # Adiciona um espaçamento de 10 pixels

        input_area_container = QWidget()  # Cria um contêiner para a área de entrada
        input_area_container_layout = QHBoxLayout(input_area_container)  # Layout horizontal para a área de entrada
        input_area_container.setStyleSheet("""
            background-color: #3e3e3f; /* Cor de fundo do retângulo */
            border: 1px solid #666; /* Borda */
            border-radius: 8px; /* Bordas arredondadas */
            padding: 5px; /* Espaçamento interno */
        """)

        # Linha de entrada e botão enviar
        self.entry = QLineEdit()  # Cria uma linha de entrada para mensagens
        self.entry.setPlaceholderText("Digite sua mensagem...")  # Define um texto de placeholder
        self.entry.setStyleSheet("""
            QLineEdit {
                background-color: #2e2e2f; /* Cor de fundo do input */
                border: none; /* Remove borda padrão */
                border-radius: 5px; /* Bordas arredondadas */
                color: white; /* Cor do texto */
                padding: 5px; /* Espaçamento interno */
            }
        """)
        # NOVO: Conectar o sinal returnPressed para enviar a mensagem
        self.entry.returnPressed.connect(self.on_send_clicked)  # Conecta a tecla Enter ao envio da mensagem
        input_area_container_layout.addWidget(self.entry)  # Adiciona a linha de entrada ao layout

        send_button = QPushButton("Enviar")  # Cria um botão para enviar mensagens
        send_button.clicked.connect(self.on_send_clicked)  # Conecta o clique do botão ao envio da mensagem
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
        input_area_container_layout.addWidget(send_button)  # Adiciona o botão de enviar ao layout

        self.chat_layout.addWidget(input_area_container)  # Adiciona a área de entrada ao layout da aba de chat

        self.tabs.addTab(self.chat_widget, "Chat")  # Adiciona a aba de chat ao QTabWidget

        if self.is_host:  # Verifica se a instância é do host
            self.settings_widget = QWidget()  # Cria um widget para a aba de configurações
            self.settings_layout = QVBoxLayout(self.settings_widget)  # Cria um layout vertical para a aba de configurações

            settings_label = QLabel("Configurações do Chat (Host):")  # Cria um label para configurações
            settings_label.setStyleSheet("color: white;")  # Define a cor do texto
            self.settings_layout.addWidget(settings_label)  # Adiciona o label ao layout de configurações
            self.settings_layout.addStretch()  # Adiciona um espaçador para empurrar o label para cima

            # Adiciona a aba de configurações ao QTabWidget
            self.tabs.addTab(self.settings_widget, "Configurações")  # Adiciona a aba de configurações ao QTabWidget

    def on_send_clicked(self):  # Método chamado ao clicar no botão de enviar ou pressionar Enter
        mensagem = self.entry.text().strip()  # Obtém o texto da linha de entrada e remove espaços em branco

        if mensagem:  # Verifica se a mensagem não está vazia
            self.add_message_to_chat(f"Você: {mensagem}")  # Adiciona a mensagem à área de chat
            self.entry.clear()  # Limpa a linha de entrada
            if self.is_host:  # Se for o host
                if self.broadcast_func:  # Se a função de broadcast estiver definida
                    self.broadcast_func(mensagem, self)  # Chama a função de broadcast com a mensagem
            else:  # Se não for o host
                if self.client:  # Se houver uma instância do cliente
                    try:
                        # Envia diretamente usando o cliente, sem dispatcher
                        self.client.send_message(mensagem)  # Envia a mensagem através do cliente
                    except Exception as e:  # Captura exceções ao enviar
                        self.add_message_to_chat(f"Erro ao enviar: {str(e)}")  # Adiciona mensagem de erro ao chat
                else:
                    self.add_message_to_chat("Erro: Conexão não disponível")  # Mensagem de erro se não houver conexão

    def add_message_to_chat(self, mensagem: str):  # Adiciona uma mensagem à área de chat
        """Adiciona uma mensagem à área de chat"""
        self.textview.append(mensagem)  # Adiciona a mensagem ao QTextEdit

