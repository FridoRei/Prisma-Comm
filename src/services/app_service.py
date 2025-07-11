import threading
from PySide6.QtWidgets import QMessageBox
from src.core.network.wifi_manager import detectar_interfaces_wifi, criar_hotspot
from src.core.network.connection_manager import verificar_conexao_com_host, obter_gateway
from src.core.chat.chat_client import ChatClient
from src.core.chat.chat_server import start_server, broadcast_from_host, stop_chat_server 
from src.services.auth_service import AuthService
from src.gui.dialogs import WifiInterfaceSelectionDialog, HotspotConfigDialog
from src.config.settings import DEFAULT_USERNAME, DEFAULT_AUTH_PORT, DEFAULT_COMM_PORT
from src.core.chat.globals import authenticated_ips, authenticated_ips_lock 
import socket

class AppService:
    def __init__(self, main_window_instance, original_stdout, original_stderr):
        self.main_window = main_window_instance
        self.auth_service = AuthService(self.main_window.auth_port, original_stdout, original_stderr)
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

                    self.auth_service.start_server()

                    # Adicionar o IP do próprio host à lista de IPs autenticados
                    # O IP do host será o gateway para os clientes
                    host_ip = obter_gateway() 
                    if host_ip:
                        with authenticated_ips_lock:
                            authenticated_ips.add(host_ip)
                            print(f"[AppService] IP do Host ({host_ip}) adicionado à lista de IPs autenticados. Lista atual: {authenticated_ips}")
                    else:
                        print("[AppService] Não foi possível obter o IP do host para adicionar à lista de autenticados.")

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
        # Primeiro, verificar a autenticação com o servidor de autenticação
        auth_success, authenticated_ip = verificar_conexao_com_host(porta=self.main_window.auth_port) # <--- ALTERADO AQUI
        
        if auth_success:
            print(f"[AppService] Autenticação com o servidor de autenticação bem-sucedida para IP: {authenticated_ip}. Adicionando à lista global.")
            # Adicionar o IP autenticado à lista global no processo principal
            if authenticated_ip:
                with authenticated_ips_lock:
                    authenticated_ips.add(authenticated_ip)
                    print(f"[AppService] IP {authenticated_ip} adicionado à lista de IPs autenticados. Lista atual: {authenticated_ips}")
            
            self.join_hotspot_chat(username)
        else:
            self.show_dialog("Erro", "Não foi possível autenticar com o host. Verifique a conexão e as portas. Você precisa se autenticar primeiro!")

    def join_hotspot_chat(self, username):
        gateway = obter_gateway()
        if not gateway:
            self.show_dialog("Erro", "Não foi possível obter o gateway da rede.")
            return

        self.disconnect_chat_client()

        self.main_window.setup_chat_widget(is_host=False)

        self.chat_client_instance = ChatClient(self.main_window.comm_port, self.main_window.chat_widget_instance, username)
        self.main_window.chat_widget_instance.client = self.chat_client_instance

        # A conexão do cliente de chat agora retorna True/False
        if self.chat_client_instance.connect():
            if self.chat_client_instance.worker:
                if self.main_window.chat_widget_instance:
                    self.chat_client_instance.worker.message_received.connect(self.main_window.chat_widget_instance.add_message_to_chat)
                    self.chat_client_instance.worker.connection_error.connect(self.main_window.chat_widget_instance.add_message_to_chat)
                    self.chat_client_instance.worker.disconnected.connect(self.main_window.on_chat_disconnected)

                self.is_connected_to_chat = True
                self.main_window.show_chat_page()
            else:
                self.show_dialog("Erro de Conexão", "O worker do cliente de chat não foi inicializado corretamente.")
                self.is_connected_to_chat = False
                self.main_window.show_home_page()
        else:
            self.show_dialog("Erro de Conexão", "Não foi possível conectar ao servidor de chat. Verifique se o host está ativo e as portas estão corretas, e se você está autenticado.")
            self.is_connected_to_chat = False
            self.main_window.show_home_page()

    def disconnect_chat_client(self):
        if self.chat_client_instance:
            if self.chat_client_instance.worker:
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
        
        # Parar o servidor de chat se estiver rodando
        if self.chat_server_thread and self.chat_server_thread.is_alive():
            print("[AppService] Sinalizando para o servidor de chat encerrar...")
            stop_chat_server() 
            self.chat_server_thread.join(timeout=2) 
            if self.chat_server_thread.is_alive():
                print("[AppService] Servidor de chat não encerrou em tempo. Pode ser necessário forçar.")
        
        # Limpar a lista de IPs autenticados ao desligar o host
        with authenticated_ips_lock:
            authenticated_ips.clear()
            print("[AppService] Lista de IPs autenticados limpa.")

        print("[AppService] Shutdown de serviços concluído.")
