from PySide6.QtWidgets import (QMainWindow, QDialog, QLabel, QPushButton, QLineEdit, QHBoxLayout, QMessageBox, QSizePolicy, QSpacerItem, QWidget, QTextEdit, QFileDialog) 
from src.core.crypto.ecc_manager import ECCManager
from PySide6.QtCore import Slot, Qt, QObject, Signal
from PySide6.QtGui import QFont
import sys
from src.gui.main_window_ui import MainWindowUI 
from src.gui.chat_widget import ChatWidget 
from src.services.app_service import AppService 
from src.config.settings import DEFAULT_USERNAME, DEFAULT_AUTH_PORT, DEFAULT_COMM_PORT
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

        self.original_stdout = None
        self.original_stderr = None

        self.app_service = None
        self.ecc_manager = ECCManager()

        self.btn_home.clicked.connect(self.show_home_page)
        self.btn_settings.clicked.connect(self.show_settings_page)
        self.btn_chat.clicked.connect(self.show_chat_page)
        self.btn_logs.clicked.connect(self.show_logs_page)

        self.btn_host.clicked.connect(self.on_host_clicked)
        self.btn_join.clicked.connect(self.on_join_clicked)

        self.username_entry.textChanged.connect(self.update_username)
        self.btn_save_settings.clicked.connect(self.save_settings)

        self.btn_load_ed25519_private_key.clicked.connect(self.load_ed25519_private_key_file)
        self.btn_load_ed25519_public_key.clicked.connect(self.load_ed25519_public_key_file)

        self.username_entry.setText(self.current_username)
        self.auth_port_entry.setText(str(self.auth_port))
        self.comm_port_entry.setText(str(self.comm_port))

        self.show_home_page()

    def handle_error(self, title, message):
        self.app_service.show_error(title, message)

    @Slot(str)
    def handle_specific_chat_error(self, message):
        self.show_dialog("Erro no Chat", message)
        self.on_chat_disconnected()

    def set_original_streams(self, stdout, stderr):
        self.original_stdout = stdout
        self.original_stderr = stderr
        self.app_service = AppService(self, self.original_stdout, self.original_stderr, self.ecc_manager)

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
        if not self.ecc_manager.has_ed25519_private_key():
            reply = QMessageBox.question(self, "Chave Ed25519 Ausente",
                                         "Nenhuma chave privada Ed25519 foi carregada para assinatura do chat. Deseja gerar e salvar uma nova chave pública agora?",
                                         QMessageBox.Yes | QMessageBox.No)
            if reply == QMessageBox.Yes:
                try:
                    self.ecc_manager.generate_ed25519_keys()
                    public_key_pem = self.ecc_manager.get_ed25519_public_key_pem()
                    
                    file_path, _ = QFileDialog.getSaveFileName(self, "Salvar Chave Pública Ed25519", "ed25519_public_key.pem", "PEM Files (*.pem);;All Files (*)")
                    if file_path:
                        with open(file_path, "wb") as f:
                            f.write(public_key_pem)
                        self.show_dialog("Sucesso", f"Chave pública Ed25519 salva em: {file_path}")          
                        self.ecc_manager.load_ed25519_public_key(public_key_pem)
                        self.ed25519_public_key_path.setText(file_path)
                    else:
                        self.show_dialog("Aviso", "Operação de salvar chave pública cancelada. O servidor pode não funcionar corretamente sem uma chave de assinatura.")                      
                        return
                except Exception as e:
                    self.show_dialog("Erro", f"Erro ao gerar/salvar chave Ed25519: {e}")
                    return 
            else:
                self.show_dialog("Aviso", "O servidor de chat pode não funcionar corretamente sem uma chave privada Ed25519 para assinatura.")
                
        if not self.ecc_manager.has_ed25519_public_key():
            self.show_dialog("Erro", "Nenhuma chave pública Ed25519 foi carregada. O servidor precisa da sua chave pública para verificar a si mesmo e para que os clientes a usem.")
            return

        self.app_service.handle_host_clicked()

    @Slot()
    def on_join_clicked(self):
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

        if self.chat_widget_instance:
            self.chat_layout.removeWidget(self.chat_widget_instance)
            self.chat_widget_instance.deleteLater()
            self.chat_widget_instance = None

        self.no_chat_label.show()
        self.show_home_page()
        self.show_dialog("Conexão Encerrada", "A conexão com o chat foi perdida.")

    @Slot()
    def load_ed25519_private_key_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Carregar Chave Privada Ed25519", "", "PEM Files (*.pem);;All Files (*)")
        if file_path:
            try:
                with open(file_path, "rb") as f:
                    key_bytes = f.read()
                self.ecc_manager.load_ed25519_private_key(key_bytes)
                self.ed25519_private_key_path.setText(file_path)
                self.show_dialog("Sucesso", "Chave privada Ed25519 carregada com sucesso!")
            except Exception as e:
                self.show_dialog("Erro", f"Erro ao carregar chave privada Ed25519: {e}")
                self.ed25519_private_key_path.clear()

    @Slot()
    def load_ed25519_public_key_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Carregar Chave Pública Ed25519", "", "PEM Files (*.pem);;All Files (*)")
        if file_path:
            try:
                with open(file_path, "rb") as f:
                    key_bytes = f.read()
                self.ecc_manager.load_ed25519_public_key(key_bytes)
                self.ed25519_public_key_path.setText(file_path)
                self.show_dialog("Sucesso", "Chave pública Ed25519 carregada com sucesso!")
            except Exception as e:
                self.show_dialog("Erro", f"Erro ao carregar chave pública Ed25519: {e}")
                self.ed25519_public_key_path.clear()

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

        from src.core.chat.chat_server import broadcast_from_host 
        self.chat_widget_instance = ChatWidget( 
            client=self.app_service.chat_client_instance, 
            is_host=is_host,
            broadcast_func=broadcast_from_host if is_host else None
        )
        self.chat_layout.addWidget(self.chat_widget_instance)

    def closeEvent(self, event):
        print("[P2P-COM] Fechando aplicação. Encerrando serviços...")
        self.app_service.shutdown() 

        print("Verificando threads ativas antes do encerramento final...")
        for thread in threading.enumerate():
            if thread.is_alive():
                print(f"  Thread ativa: {thread.name} (Daemon: {thread.daemon})")

        event.accept()

