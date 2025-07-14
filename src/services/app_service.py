import threading
from PySide6.QtWidgets import QMessageBox, QDialog
from src.core.network.connection_manager import verificar_conexao_com_host, obter_gateway, obter_gateway_generico 
from src.core.chat.chat_client import ChatClient
from src.core.chat.chat_server import start_server, broadcast_from_host
from src.services.auth_service import AuthService
from src.config.settings import DEFAULT_USERNAME, DEFAULT_AUTH_PORT, DEFAULT_COMM_PORT
from src.core.chat.globals import authenticated_ips, authenticated_ips_lock, temp_rsa_managers, temp_rsa_managers_lock
import socket
from src.gui.dialogs import JoinOptionDialog 

class AppService:
    def __init__(self, main_window_instance, original_stdout, original_stderr):
        self.main_window = main_window_instance
        self.auth_service = AuthService()
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
        self.auth_service.start_server()
        
        self.main_window.setup_chat_widget(is_host=True)
        self.is_connected_to_chat = True
        
        ips_locais = obter_gateway_generico()         
        if ips_locais:
            ips_str = ", ".join(ips_locais)
            self.main_window.show_dialog("Servidor Iniciado", 
                                          f"Servidor de autenticação e chat iniciados.\n"
                                          f"Compartilhe o seguinte IP com os clientes:\n"
                                          f"{ips_str}\n" 
                                          f"Porta de Autenticação: {self.main_window.auth_port}\n"
                                          f"Porta de Comunicação: {self.main_window.comm_port}")
        else:
            self.main_window.show_dialog("Erro", "Não foi possível obter o IP local. Verifique sua conexão de rede.")
            ips_locais = ['127.0.0.1'] 

        with authenticated_ips_lock:
            for ip in ips_locais: 
                authenticated_ips.add(ip)

        self.chat_server_thread = threading.Thread(
            target=start_server,
            args=(self.main_window.chat_widget_instance, self.main_window.comm_port),
            daemon=True
        )
        self.chat_server_thread.start()

    def handle_join_clicked(self, username):
        join_dialog = JoinOptionDialog(self.main_window)
        if join_dialog.exec() == QDialog.Accepted:
            server_ip_to_use = None
            
            if join_dialog.use_gateway:
                server_ip_to_use = obter_gateway()
                print(f"[DEBUG] Usando gateway: {server_ip_to_use}")
            else:
                server_ip_to_use = join_dialog.server_ip
            if not self.server_ip_to_validate(server_ip_to_use):
                self.show_dialog("Erro", "Endereço IP inválido.")
                return
            if verificar_conexao_com_host(server_ip_to_use, self.main_window.auth_port):
                self.join_hotspot_chat(server_ip_to_use, username)
            else:
                self.show_dialog("Erro", f"Falha na conexão com {server_ip_to_use}")
                
    def server_ip_to_validate(self, ip):
        """Valida formato do IP"""
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False

    def join_hotspot_chat(self, server_ip, username): 
        self.disconnect_chat_client()

        self.main_window.setup_chat_widget(is_host=False)

        self.chat_client_instance = ChatClient(server_ip, self.main_window.comm_port, self.main_window.chat_widget_instance, username)
        self.main_window.chat_widget_instance.client = self.chat_client_instance

        self.chat_client_instance.connect()

        if self.chat_client_instance.worker:
            if self.main_window.chat_widget_instance:
                self.chat_client_instance.worker.message_received.connect(self.main_window.chat_widget_instance.add_message_to_chat)
                self.chat_client_instance.worker.connection_error.connect(self.main_window.chat_widget_instance.add_message_to_chat)
                self.chat_client_instance.worker.disconnected.connect(self.main_window.on_chat_disconnected)

            self.is_connected_to_chat = True
            self.main_window.show_chat_page()
        else:
            self.show_dialog("Erro de Conexão", "Não foi possível conectar ao servidor de chat. Verifique se o host está ativo e as portas estão corretas.")
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
        print("[AppService] Shutdown de serviços concluído.")
        
        with authenticated_ips_lock:
            authenticated_ips.clear()
            print("[AppService] Lista de IPs autenticados limpa.")
        with temp_rsa_managers_lock:
            for ip in list(temp_rsa_managers.keys()): 
                if ip in temp_rsa_managers:
                    temp_rsa_managers[ip]["manager"].clear_keys()
                    del temp_rsa_managers[ip]         
