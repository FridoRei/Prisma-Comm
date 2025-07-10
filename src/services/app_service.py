# src/services/app_service.py
import threading
from PySide6.QtWidgets import QMessageBox
from src.core.network.wifi_manager import detectar_interfaces_wifi, criar_hotspot
from src.core.network.connection_manager import verificar_conexao_com_host, obter_gateway
from src.core.chat.chat_client import ChatClient
from src.core.chat.chat_server import start_server, broadcast_from_host
from src.services.auth_service import AuthService
from src.gui.dialogs import WifiInterfaceSelectionDialog, HotspotConfigDialog
from src.config.settings import DEFAULT_USERNAME, DEFAULT_AUTH_PORT, DEFAULT_COMM_PORT

class AppService:
    def __init__(self, main_window_instance):
        self.main_window = main_window_instance
        self.auth_service = AuthService(self.main_window.auth_port)
        self.chat_client_instance = None
        self.chat_server_thread = None
        self.is_connected_to_chat = False

    def show_dialog(self, title, message):
        msg = QMessageBox(self.main_window)
        msg.setWindowTitle(title)
        msg.setText(message)
        msg.setIcon(QMessageBox.Information)
        msg.exec()

    def handle_host_clicked(self):
        interfaces = detectar_interfaces_wifi()
        if not interfaces:
            self.show_dialog("Erro", "Nenhuma interface Wi-Fi encontrada.")
            return

        iface_dialog = WifiInterfaceSelectionDialog(self.main_window)
        if iface_dialog.exec() == WifiInterfaceSelectionDialog.Accepted:
            selected_interface = iface_dialog.selected_interface
            if not selected_interface:
                self.show_dialog("Erro", "Nenhuma interface selecionada.")
                return

            hotspot_dialog = HotspotConfigDialog(self.main_window)
            if hotspot_dialog.exec() == HotspotConfigDialog.Accepted:
                ssid = hotspot_dialog.ssid
                password = hotspot_dialog.password

                try:
                    criar_hotspot(selected_interface, ssid, password)
                    self.show_dialog("Hotspot criado", f"SSID: {ssid}\nSenha: {password}")

                    # Inicia o servidor de autenticação
                    self.auth_service.start_server()

                    # Configura e inicia o servidor de chat
                    self.main_window.setup_chat_widget(is_host=True)
                    self.is_connected_to_chat = True
                    self.main_window.show_chat_page()

                    self.chat_server_thread = threading.Thread(
                        target=start_server,
                        args=(self.main_window.chat_widget_instance, self.main_window.comm_port),
                        daemon=True
                    )
                    self.chat_server_thread.start()

                except Exception as e:
                    self.show_dialog("Erro", f"Não foi possível criar o hotspot ou iniciar serviços: {e}")
                    print(f"[AppService] Erro ao hospedar: {e}")
            else:
                self.show_dialog("Cancelado", "Criação do hotspot cancelada.")
        else:
            self.show_dialog("Cancelado", "Seleção de interface cancelada.")

    def handle_join_clicked(self, username):
        # Passo 1: Tentar autenticar com o servidor de autenticação (porta 20556)
        print("[AppService] Tentando autenticar com o host...")
        if verificar_conexao_com_host(porta=self.main_window.auth_port):
            print("[AppService] Autenticação com o host bem-sucedida!")
            # Passo 2: Se a autenticação for bem-sucedida, então tentar se juntar ao chat
            self.join_hotspot_chat(username)
        else:
            # Passo 3: Se a autenticação falhar, exibir mensagem de erro e não tentar conectar ao chat
            self.show_dialog("Erro de Autenticação", "Não foi possível autenticar com o host. Verifique a conexão e as portas, ou se o host está ativo.")
            print("[AppService] Autenticação com o host falhou.")


    def join_hotspot_chat(self, username):
        gateway = obter_gateway()
        if not gateway:
            self.show_dialog("Erro", "Não foi possível obter o gateway da rede.")
            return

        self.disconnect_chat_client() # Garante que qualquer cliente anterior seja desconectado

        self.main_window.setup_chat_widget(is_host=False) # Configura o widget de chat na GUI

        # Cria uma nova instância do ChatClient
        self.chat_client_instance = ChatClient(self.main_window.comm_port, self.main_window.chat_widget_instance, username)
        self.main_window.chat_widget_instance.client = self.chat_client_instance

        # Tenta conectar o cliente de chat. A lógica de recusa por não autorizado está no chat_server.py
        self.chat_client_instance.connect()

        # Verifica se a conexão foi bem-sucedida (o worker foi criado e a conexão estabelecida)
        # Note: A conexão pode ser estabelecida, mas o servidor de chat ainda pode recusar a comunicação
        # se o IP não estiver na lista de autorizados. O ChatClientWorker lida com a mensagem "AUTH_REQUIRED_CHAT".
        if self.chat_client_instance.worker:
            if self.main_window.chat_widget_instance:
                self.chat_client_instance.worker.message_received.connect(self.main_window.chat_widget_instance.add_message_to_chat)
                self.chat_client_instance.worker.connection_error.connect(self.main_window.chat_widget_instance.add_message_to_chat)
                self.chat_client_instance.worker.disconnected.connect(self.main_window.on_chat_disconnected)

            self.is_connected_to_chat = True
            self.main_window.show_chat_page()
            print("[AppService] Tentativa de conexão ao chat iniciada. Verifique o log para status.")
        else:
            self.show_dialog("Erro de Conexão", "Não foi possível iniciar a conexão com o servidor de chat. Verifique se o host está ativo e as portas estão corretas.")
            self.is_connected_to_chat = False
            self.main_window.show_home_page() # Volta para a página inicial se a conexão falhar

    def disconnect_chat_client(self):
        if self.chat_client_instance:
            if self.chat_client_instance.worker:
                # Desconecta os sinais para evitar chamadas a objetos já deletados
                if self.main_window.chat_widget_instance:
                    try:
                        self.chat_client_instance.worker.message_received.disconnect(self.main_window.chat_widget_instance.add_message_to_chat)
                    except TypeError: pass
                    try:
                        self.chat_client_instance.worker.connection_error.disconnect(self.main_window.chat_widget_instance.add_message_to_chat)
                    except TypeError: pass
                    try:
                        self.chat_client_instance.worker.disconnected.disconnect(self.main_window.on_chat_disconnected)
                    except TypeError: pass
                self.chat_client_instance.worker.stop()
                self.chat_client_instance.worker = None
            self.chat_client_instance.disconnect()
            self.chat_client_instance = None
            print("[AppService] Cliente de chat desconectado.")

    def shutdown(self):
        print("[AppService] Iniciando shutdown de serviços...")
        self.auth_service.stop_server()
        self.disconnect_chat_client()
        print("[AppService] Shutdown de serviços concluído.")
