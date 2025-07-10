from PySide6.QtWidgets import (QMainWindow, QDialog, QLabel, QPushButton, QVBoxLayout, QLineEdit, QHBoxLayout, QMessageBox, QSizePolicy, QSpacerItem, QWidget, QTextEdit)
from PySide6.QtCore import Slot, Qt, QObject, Signal
from PySide6.QtGui import QFont

from src.gui.main_window_ui import MainWindowUI # Nova importação
from src.gui.chat_widget import ChatWidget # Nova importação
from src.services.app_service import AppService # Nova importação
from src.config.settings import DEFAULT_USERNAME, DEFAULT_AUTH_PORT, DEFAULT_COMM_PORT # Nova importação
import threading

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.ui = MainWindowUI()
        self.ui.setup_ui(self)

        self.setMinimumSize(800, 400)

        self.current_username = DEFAULT_USERNAME
        self.auth_port = DEFAULT_AUTH_PORT
        self.comm_port = DEFAULT_COMM_PORT

        self.chat_widget_instance = None
        self.is_connected_to_chat = False

        # Instancia o AppService, passando a si mesmo como referência
        self.app_service = AppService(self)

        self.btn_home.clicked.connect(self.show_home_page)
        self.btn_settings.clicked.connect(self.show_settings_page)
        self.btn_chat.clicked.connect(self.show_chat_page)
        self.btn_logs.clicked.connect(self.show_logs_page)

        # Conecta os botões aos métodos do AppService
        self.btn_host.clicked.connect(self.on_host_clicked)
        self.btn_join.clicked.connect(self.on_join_clicked)

        self.username_entry.textChanged.connect(self.update_username)
        self.btn_save_settings.clicked.connect(self.save_settings)

        self.username_entry.setText(self.current_username)
        self.auth_port_entry.setText(str(self.auth_port))
        self.comm_port_entry.setText(str(self.comm_port))

        self.show_home_page()

        # O redirecionamento de logs agora é feito em main.py e conectado aqui
        # self.redirect_stdout_stderr() # Removido daqui

    # O método append_log_message permanece aqui para ser o slot do sinal
    @Slot(str)
    def append_log_message(self, message):
        self.logs_text_edit.append(message.strip())
        self.logs_text_edit.verticalScrollBar().setValue(self.logs_text_edit.verticalScrollBar().maximum())

    @Slot()
    def update_username(self, text):
        self.current_username = text.strip() or DEFAULT_USERNAME

    @Slot()
    def show_home_page(self):
        self.stacked_widget.setCurrentWidget(self.home_page)
        self.setWindowTitle("Conexão Segura - Início")

    @Slot()
    def show_settings_page(self):
        self.stacked_widget.setCurrentWidget(self.settings_page)
        self.setWindowTitle("Conexão Segura - Configurações")
        self.username_entry.setText(self.current_username if self.current_username != DEFAULT_USERNAME else "")
        self.auth_port_entry.setText(str(self.auth_port))
        self.comm_port_entry.setText(str(self.comm_port))

    @Slot()
    def show_chat_page(self):
        self.stacked_widget.setCurrentWidget(self.chat_page)
        self.setWindowTitle("Conexão Segura - Chat")

    @Slot()
    def show_logs_page(self):
        self.stacked_widget.setCurrentWidget(self.logs_page)
        self.setWindowTitle("Conexão Segura - Logs")

    @Slot()
    def save_settings(self):
        try:
            auth_port_str = self.auth_port_entry.text().strip()
            comm_port_str = self.comm_port_entry.text().strip()

            if not auth_port_str.isdigit() or not comm_port_str.isdigit():
                raise ValueError("As portas devem conter apenas números.")

            auth_port = int(auth_port_str)
            comm_port = int(comm_port_str)

            if not (100 <= auth_port <= 65535):
                raise ValueError("A porta de autenticação deve estar entre 100 e 65535.")
            if not (100 <= comm_port <= 65535):
                raise ValueError("A porta de comunicação deve estar entre 100 e 65535.")

            if auth_port == comm_port:
                raise ValueError("As portas de autenticação e comunicação não podem ser iguais.")

            self.auth_port = auth_port
            self.comm_port = comm_port
            self.show_dialog("Sucesso", "Configurações de portas salvas com sucesso!")

        except ValueError as e:
            self.show_dialog("Erro", f"Erro ao salvar configurações: {str(e)}")
        except Exception as e:
            self.show_dialog("Erro", f"Ocorreu um erro inesperado: {str(e)}")

    @Slot()
    def on_host_clicked(self):
        # Delega a lógica para o AppService
        self.app_service.handle_host_clicked()

    @Slot()
    def on_join_clicked(self):
        # Delega a lógica para o AppService
        self.app_service.handle_join_clicked(self.current_username)

    def show_dialog(self, titulo, mensagem):
        msg = QMessageBox(self)
        msg.setWindowTitle(titulo)
        msg.setText(mensagem)
        msg.setIcon(QMessageBox.Information)
        msg.exec()

    @Slot()
    def on_chat_disconnected(self):
        print("Chat desconectado. Resetando interface.")
        self.is_connected_to_chat = False

        # A lógica de desconexão do cliente agora está no AppService
        # self.app_service.disconnect_chat_client() # Não chamar aqui para evitar loop ou duplicação

        if self.chat_widget_instance:
            self.chat_layout.removeWidget(self.chat_widget_instance)
            self.chat_widget_instance.deleteLater()
            self.chat_widget_instance = None

        self.no_chat_label.show()
        self.show_home_page()
        self.show_dialog("Conexão Encerrada", "A conexão com o chat foi perdida.")

    def setup_chat_widget(self, is_host: bool):
        self.no_chat_label.hide()

        for i in reversed(range(self.chat_layout.count())):
            item = self.chat_layout.itemAt(i)
            if item.widget() and item.widget() != self.no_chat_label:
                widget_to_delete = self.chat_layout.takeAt(i).widget()
                if widget_to_delete:
                    widget_to_delete.deleteLater()

        if self.chat_widget_instance and self.chat_widget_instance.parent() == self.chat_page:
            self.chat_layout.removeWidget(self.chat_widget_instance)
            self.chat_widget_instance.deleteLater()
            self.chat_widget_instance = None

        # Passa a função de broadcast do chat_server para o ChatWidget se for host
        from src.core.chat.chat_server import broadcast_from_host # Importação local para evitar circular
        self.chat_widget_instance = ChatWidget( # Usando ChatWidget
            client=self.app_service.chat_client_instance, # Pega o cliente do app_service
            is_host=is_host,
            broadcast_func=broadcast_from_host if is_host else None
        )
        self.chat_layout.addWidget(self.chat_widget_instance)

    def closeEvent(self, event):
        print("[P2P-COM] Fechando aplicação. Encerrando serviços...")
        self.app_service.shutdown() # Delega o shutdown para o AppService

        print("Verificando threads ativas antes do encerramento final...")
        for thread in threading.enumerate():
            if thread.is_alive():
                print(f"  Thread ativa: {thread.name} (Daemon: {thread.daemon})")

        # Não é mais necessário chamar QApplication.instance().quit() aqui,
        # pois sys.exit(app.exec()) em main.py já cuida disso.
        event.accept()

