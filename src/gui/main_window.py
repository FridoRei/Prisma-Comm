from PySide6.QtWidgets import (QMainWindow, QDialog, QLabel, QPushButton, QLineEdit, QHBoxLayout, QMessageBox, QSizePolicy, QSpacerItem, QWidget, QTextEdit, QFileDialog)
from src.core.crypto.ecc_manager import ECCManager
from PySide6.QtCore import Slot, Qt, QObject, Signal
from PySide6.QtGui import QFont
import sys
from src.gui.main_window_ui import MainWindowUI
from src.gui.chat_widget import ChatWidget
from src.services.app_service import AppService
from src.gui.dialogs import PasswordInputDialog, Ed25519ChannelSelectionDialog, AdvancedTimeoutDialog
from src.config.settings import (
    DEFAULT_USERNAME, DEFAULT_AUTH_PORT, DEFAULT_COMM_PORT, ED25519_CHANNELS,
    DEFAULT_CLIENT_RSA_TIMEOUT, DEFAULT_CLIENT_PASSWORD_RESPONSE_TIMEOUT,
    DEFAULT_CLIENT_MESSAGE_RECEIVE_TIMEOUT, DEFAULT_CLIENT_HANDSHAKE_TIMEOUT,
    DEFAULT_HOST_UDP_OPERATION_TIMEOUT, DEFAULT_HOST_CLIENT_DATA_RECEIVE_TIMEOUT
)
from src.gui.dialogs import PasswordInputDialog, Ed25519ChannelSelectionDialog
import threading
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.ui = MainWindowUI()
<<<<<<< HEAD
        self.ui.setup_ui(self)
=======
        self.ed25519_channel_widgets = self.ui.setup_ui(self)
>>>>>>> Dev

        self.setMinimumSize(800, 400)

        self.current_username = DEFAULT_USERNAME
        self.auth_port = DEFAULT_AUTH_PORT
        self.comm_port = DEFAULT_COMM_PORT
        self.host_password = None

        self.chat_widget_instance = None
        self.is_connected_to_chat = False

        self.original_stdout = None
        self.original_stderr = None

        self.app_service = None
        self.ecc_manager = ECCManager()

        self.ed25519_keys = {
            channel: {"private": None, "public": None, "path_private": "", "path_public": ""}
            for channel in ED25519_CHANNELS
        }
        
        self.timeout_settings = {
            "client_rsa_timeout": DEFAULT_CLIENT_RSA_TIMEOUT,
            "client_password_response_timeout": DEFAULT_CLIENT_PASSWORD_RESPONSE_TIMEOUT,
            "client_message_receive_timeout": DEFAULT_CLIENT_MESSAGE_RECEIVE_TIMEOUT,
            "client_handshake_timeout": DEFAULT_CLIENT_HANDSHAKE_TIMEOUT,
            "host_udp_operation_timeout": DEFAULT_HOST_UDP_OPERATION_TIMEOUT,
            "host_client_data_receive_timeout": DEFAULT_HOST_CLIENT_DATA_RECEIVE_TIMEOUT
        }        

        for channel_name in ED25519_CHANNELS:
            widgets = self.ed25519_channel_widgets[channel_name]
            widgets["btn_load_private"].clicked.connect(lambda checked, c=channel_name: self.load_ed25519_private_key_file(c))
            widgets["btn_load_public"].clicked.connect(lambda checked, c=channel_name: self.load_ed25519_public_key_file(c))

        self.btn_home.clicked.connect(self.show_home_page)
        self.btn_settings.clicked.connect(self.show_settings_page)
        self.btn_chat.clicked.connect(self.show_chat_page)
        self.btn_logs.clicked.connect(self.show_logs_page)

        self.btn_host.clicked.connect(self.on_host_clicked)
        self.btn_join.clicked.connect(self.on_join_clicked)
        self.btn_advanced_timeout_options.clicked.connect(self.show_advanced_timeout_dialog)

        self.username_entry.textChanged.connect(self.update_username)
        self.btn_save_settings.clicked.connect(self.save_settings)

        self.username_entry.setText(self.current_username)
        self.auth_port_entry.setText(str(self.auth_port))
        self.comm_port_entry.setText(str(self.comm_port))

        self.show_home_page()

    def handle_error(self, title, message):
<<<<<<< HEAD
        if self.app_service:
            self.app_service.show_error(title, message)
        else:
            print(f"Erro: {title} - {message}")
=======
        print(f"[ERROR] [MainWindow] Erro: {title} - {message}")

    @Slot(str)
    def handle_specific_chat_error(self, message):
        self.show_dialog("Erro no Chat", message)
        print(f"[ERROR] [MainWindow] Erro específico do chat: {message}")
        self.on_chat_disconnected()
>>>>>>> Dev

    def set_original_streams(self, stdout, stderr):
        self.original_stdout = stdout
        self.original_stderr = stderr
        self.app_service = AppService(self, self.original_stdout, self.original_stderr, self.ecc_manager, self.timeout_settings)
        print("[INFO] [MainWindow] AppService inicializado.")

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
        self.setWindowTitle("Prisma Comm - Início")

    @Slot()
    def show_settings_page(self):
        self.stacked_widget.setCurrentWidget(self.settings_page)
        self.setWindowTitle("Prisma Comm - Configurações")
        self.username_entry.setText(self.current_username if self.current_username != DEFAULT_USERNAME else "")
        self.auth_port_entry.setText(str(self.auth_port))
        self.comm_port_entry.setText(str(self.comm_port))
        for channel_name in ED25519_CHANNELS:
            widgets = self.ed25519_channel_widgets[channel_name]
            widgets["private_path_entry"].setText(self.ed25519_keys[channel_name]["path_private"])
            widgets["public_path_entry"].setText(self.ed25519_keys[channel_name]["path_public"])

    @Slot()
    def show_chat_page(self):
        self.stacked_widget.setCurrentWidget(self.chat_page)
        self.setWindowTitle("Prisma Comm - Chat")

    @Slot()
    def show_logs_page(self):
        self.stacked_widget.setCurrentWidget(self.logs_page)
        self.setWindowTitle("Prisma Comm - Logs")

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
            self.app_service.auth_service.auth_port = auth_port
            self.app_service.comm_port = comm_port
            self.show_dialog("Sucesso", "Configurações de portas salvas com sucesso!")
            print(f"[SUCCESS] [MainWindow] Configurações de portas salvas: Auth={self.auth_port}, Comm={self.comm_port}.")

        except ValueError as e:
            self.show_dialog("Erro", f"Erro ao salvar configurações: {str(e)}")
            print(f"[ERROR] [MainWindow] Erro de validação ao salvar configurações: {e}")
        except Exception as e:
            self.show_dialog("Erro", f"Ocorreu um erro inesperado ao salvar configurações: {str(e)}")
            print(f"[CRITICAL] [MainWindow] Erro inesperado ao salvar configurações: {e}")


    @Slot()
    def show_advanced_timeout_dialog(self):
        timeout_dialog = AdvancedTimeoutDialog(self, self.timeout_settings)
        if timeout_dialog.exec() == QDialog.Accepted:
            self.timeout_settings = timeout_dialog.get_timeouts()
            self.app_service.update_timeout_settings(self.timeout_settings)
            self.show_dialog("Sucesso", "Configurações de timeout salvas com sucesso!")
        else:
            self.show_dialog("Aviso", "Configurações de timeout não foram salvas.")

    @Slot()
    def on_host_clicked(self):
        password_dialog = PasswordInputDialog(self, title="Senha do Host", message="Defina a senha para os clientes se conectarem:")
        if password_dialog.exec() == QDialog.Accepted:
            self.host_password = password_dialog.password
        else:
            self.show_dialog("Aviso", "Operação de hospedar rede cancelada. Senha não fornecida.")
            return

        available_private_channels = [
            c for c in ED25519_CHANNELS if self.ed25519_keys[c]["private"] is not None
        ]

        selected_private_channel = None
        if not available_private_channels:
            reply = QMessageBox.question(self, "Chave Ed25519 Ausente",
                                         "Nenhuma chave privada Ed25519 foi carregada para assinatura do chat. Deseja gerar e salvar uma nova chave agora?",
                                         QMessageBox.Yes | QMessageBox.No)
            if reply == QMessageBox.Yes:
                try:
                    first_available_channel = ED25519_CHANNELS[0]
                    self.ecc_manager.generate_ed25519_keys()
                    private_key_pem = self.ecc_manager.get_ed25519_private_key_pem()
                    public_key_pem = self.ecc_manager.get_ed25519_public_key_pem()

                    file_path_private, _ = QFileDialog.getSaveFileName(self, f"Salvar Chave Privada Ed25519 ({first_available_channel.capitalize()})", f"ed25519_private_key_{first_available_channel}.pem", "PEM Files (*.pem);;All Files (*)")
                    if file_path_private:
                        with open(file_path_private, "wb") as f:
                            f.write(private_key_pem)
                        self.ed25519_keys[first_available_channel]["private"] = self.ecc_manager._ed25519_private_key
                        self.ed25519_keys[first_available_channel]["path_private"] = file_path_private
                        self.ed25519_channel_widgets[first_available_channel]["private_path_entry"].setText(file_path_private)
                        self.show_dialog("Sucesso", f"Chave privada Ed25519 salva em: {file_path_private}")
                    else:
                        self.show_dialog("Aviso", "Operação de salvar chave privada cancelada. O servidor pode não funcionar corretamente sem uma chave de assinatura.")
                        return

                    file_path_public, _ = QFileDialog.getSaveFileName(self, f"Salvar Chave Pública Ed25519 ({first_available_channel.capitalize()})", f"ed25519_public_key_{first_available_channel}.pem", "PEM Files (*.pem);;All Files (*)")
                    if file_path_public:
                        with open(file_path_public, "wb") as f:
                            f.write(public_key_pem)
                        self.ed25519_keys[first_available_channel]["public"] = self.ecc_manager._ed25519_public_key
                        self.ed25519_keys[first_available_channel]["path_public"] = file_path_public
                        self.ed25519_channel_widgets[first_available_channel]["public_path_entry"].setText(file_path_public)
                        self.show_dialog("Sucesso", f"Chave pública Ed25519 salva em: {file_path_public}")
                    else:
                        self.show_dialog("Aviso", "Operação de salvar chave pública cancelada. O servidor pode não funcionar corretamente sem uma chave de assinatura.")
                        return

                    available_private_channels = [first_available_channel] 

                except Exception as e:
                    self.show_dialog("Erro", f"Erro ao gerar/salvar chaves Ed25519: {e}")
                    print(f"[ERROR] [MainWindow] Erro ao gerar/salvar chaves Ed25519: {e}")
                    return
            else:
                self.show_dialog("Aviso", "O servidor de chat pode não funcionar corretamente sem uma chave privada Ed25519 para assinatura.")
                self.show_dialog("Erro", "Nenhuma chave privada Ed25519 disponível. A hospedagem foi cancelada, pois a segurança do chat não pode ser garantida.")
                return


        if len(available_private_channels) > 1:
            channel_dialog = Ed25519ChannelSelectionDialog(self, available_channels=available_private_channels, key_type="privada")
            if channel_dialog.exec() == QDialog.Accepted:
                selected_private_channel = channel_dialog.selected_channel
            else:
                self.show_dialog("Aviso", "Operação de hospedar rede cancelada. Canal de chave privada não selecionado.")
                return
        elif len(available_private_channels) == 1:
            selected_private_channel = available_private_channels[0]
        else:
            self.show_dialog("Erro", "Nenhuma chave privada Ed25519 disponível para iniciar o servidor de chat. A hospedagem foi cancelada.")
            return

        self.app_service.handle_host_clicked(
            self.host_password,
            self.ed25519_keys[selected_private_channel]["private"]
        )

    @Slot()
    def on_join_clicked(self):
        password_dialog = PasswordInputDialog(self, title="Senha do Host", message="Por favor, insira a senha do host:")
        if password_dialog.exec() == QDialog.Accepted:
            client_password = password_dialog.password
        else:
            self.show_dialog("Aviso", "Operação de juntar-se à rede cancelada. Senha não fornecida.")
            return

        available_public_channels = [
            c for c in ED25519_CHANNELS if self.ed25519_keys[c]["public"] is not None
        ]

        if not available_public_channels:
            self.show_dialog("Erro", "Nenhuma chave pública Ed25519 carregada. Não é possível verificar a assinatura do servidor. A junção foi cancelada.")
            return

        selected_public_channel = None
        if len(available_public_channels) > 1:
            channel_dialog = Ed25519ChannelSelectionDialog(self, available_channels=available_public_channels, key_type="pública")
            if channel_dialog.exec() == QDialog.Accepted:
                selected_public_channel = channel_dialog.selected_channel
            else:
                self.show_dialog("Aviso", "Operação de juntar-se à rede cancelada. Canal de chave pública não selecionado.")
                return
        elif len(available_public_channels) == 1:
            selected_public_channel = available_public_channels[0]
        else:
            self.show_dialog("Erro", "Nenhuma chave pública Ed25519 disponível para verificar a assinatura do servidor. A junção foi cancelada.")
            print("[ERROR] [MainWindow] Nenhuma chave pública Ed25519 disponível, junção cancelada.")
            return

        try:
            client_ed25519_public_key_bytes = self.ed25519_keys[selected_public_channel]["public"].public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        except Exception as e:
            self.show_dialog("Erro", f"Erro ao serializar a chave pública Ed25519 para o canal '{selected_public_channel.capitalize()}': {e}. A junção foi cancelada.")
            print(f"[ERROR] [MainWindow] Erro ao serializar chave pública Ed25519: {e}. Junção cancelada.")
            return

        self.app_service.handle_join_clicked(
            self.current_username,
            client_password,
            client_ed25519_public_key_bytes
        )

    def show_dialog(self, titulo, mensagem):
        msg = QMessageBox(self)
        msg.setWindowTitle(titulo)
        msg.setText(mensagem)
        msg.setIcon(QMessageBox.Information)
        msg.exec()


    @Slot()
    def on_chat_disconnected(self):
        print("[INFO] [MainWindow] Chat desconectado. Resetando interface.")
        self.is_connected_to_chat = False

        if self.chat_widget_instance:
            self.chat_layout.removeWidget(self.chat_widget_instance)
            self.chat_widget_instance.deleteLater()
            self.chat_widget_instance = None

        self.no_chat_label.show()
        self.show_home_page()
        self.show_dialog("Conexão Encerrada", "A conexão com o chat foi perdida.")

    @Slot()
    def load_ed25519_private_key_file(self, channel_name: str):
        file_path, _ = QFileDialog.getOpenFileName(self, f"Carregar Chave Privada Ed25519 ({channel_name.capitalize()})", "", "PEM Files (*.pem);;All Files (*)")
        if file_path:
            try:
                with open(file_path, "rb") as f:
                    key_bytes = f.read()
                temp_ecc_manager = ECCManager()
                temp_ecc_manager.load_ed25519_private_key(key_bytes)
                self.ed25519_keys[channel_name]["private"] = temp_ecc_manager._ed25519_private_key
                self.ed25519_keys[channel_name]["path_private"] = file_path
                self.ed25519_channel_widgets[channel_name]["private_path_entry"].setText(file_path)
                self.show_dialog("Sucesso", f"Chave privada Ed25519 do canal '{channel_name.capitalize()}' carregada com sucesso!")
            except Exception as e:
                self.show_dialog("Erro", f"Erro ao carregar chave privada Ed25519 do canal '{channel_name.capitalize()}': {e}")
                print(f"[ERROR] [MainWindow] Erro ao carregar chave privada Ed25519 para '{channel_name}': {e}")
                self.ed25519_keys[channel_name]["private"] = None
                self.ed25519_keys[channel_name]["path_private"] = ""
                self.ed25519_channel_widgets[channel_name]["private_path_entry"].clear()

    @Slot()
    def load_ed25519_public_key_file(self, channel_name: str):
        file_path, _ = QFileDialog.getOpenFileName(self, f"Carregar Chave Pública Ed25519 ({channel_name.capitalize()})", "", "PEM Files (*.pem);;All Files (*)")
        if file_path:
            try:
                with open(file_path, "rb") as f:
                    key_bytes = f.read()
                temp_ecc_manager = ECCManager()
                temp_ecc_manager.load_ed25519_public_key(key_bytes)
                self.ed25519_keys[channel_name]["public"] = temp_ecc_manager._ed25519_public_key
                self.ed25519_keys[channel_name]["path_public"] = file_path
                self.ed25519_channel_widgets[channel_name]["public_path_entry"].setText(file_path)
                self.show_dialog("Sucesso", f"Chave pública Ed25519 do canal '{channel_name.capitalize()}' carregada com sucesso!")
            except Exception as e:
                self.show_dialog("Erro", f"Erro ao carregar chave pública Ed25519 do canal '{channel_name.capitalize()}': {e}")
                print(f"[ERROR] [MainWindow] Erro ao carregar chave pública Ed25519 para '{channel_name}': {e}")
                self.ed25519_keys[channel_name]["public"] = None
                self.ed25519_keys[channel_name]["path_public"] = ""
                self.ed25519_channel_widgets[channel_name]["public_path_entry"].clear()

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
        print("[INFO] [MainWindow] Sinalizando shutdown para AppService...")
        self.app_service.shutdown()

        print("[INFO] [MainWindow] Verificando threads ativas antes do encerramento final...")
        for thread in threading.enumerate():
            if thread.is_alive():
                print(f"[DEBUG] [MainWindow] Thread ativa: {thread.name} (Daemon: {thread.daemon})")

        event.accept()
        print("[INFO] [MainWindow] Aplicação encerrada.")

