import threading
from PySide6.QtWidgets import QMessageBox, QDialog
from src.core.network.connection_manager import verificar_conexao_com_host, obter_gateway, obter_gateway_generico
from src.core.chat.chat_client import ChatClient
from src.core.chat.chat_server import start_server, stop_chat_server 
from src.services.auth_service import AuthService
from src.config.settings import DEFAULT_USERNAME, DEFAULT_AUTH_PORT, DEFAULT_COMM_PORT
from src.core.chat.globals import authenticated_ips, authenticated_ips_lock, temp_rsa_managers, temp_rsa_managers_lock, connected_users, connected_users_lock
import socket
from src.core.crypto.ecc_manager import ECCManager
from src.gui.dialogs import JoinOptionDialog
from cryptography.hazmat.primitives.asymmetric import ed25519 
from src.core.network.dos_detector import DoSDetector

class AppService:
    def __init__(self, main_window_instance, original_stdout, original_stderr, ecc_manager):
        self.main_window = main_window_instance
        self.dos_detector = DoSDetector()
        self.auth_service = AuthService(auth_port=self.main_window.auth_port, dos_detector=self.dos_detector) 
        self.chat_client_instance = None
        self.chat_server_thread = None
        self.is_connected_to_chat = False
        self.ecc_manager = ecc_manager

    def show_error(self, title, message, critical=False):
        message_box = QMessageBox(self.main_window)
        message_box.setWindowTitle(title)
        message_box.setText(message)
        message_box.setIcon(QMessageBox.Critical if critical else QMessageBox.Warning)
        message_box.exec()
        print(f"[ERROR] [AppService] Erro exibido ao usuário: {title} - {message}")

    def show_dialog(self, title, message):
        msg = QMessageBox(self.main_window)
        msg.setWindowTitle(title)
        msg.setText(message)
        msg.setIcon(QMessageBox.Information)
        msg.exec()

    def handle_host_clicked(self, host_password: str, host_ed25519_private_key: ed25519.Ed25519PrivateKey):
        try:
            self.auth_service.start_server(host_password)
        except Exception as e:
            self.show_error("Erro ao Iniciar Servidor", f"Não foi possível iniciar o servidor de autenticação: {e}")
            print(f"[CRITICAL] [AppService] Falha ao iniciar servidor de autenticação: {e}")
            return

        self.main_window.setup_chat_widget(is_host=True)
        self.is_connected_to_chat = True

        ips_locais = obter_gateway_generico()
        if ips_locais:
            ips_str = ", ".join(ips_locais)
            self.show_dialog("Servidor Iniciado",
                                          f"Servidor de autenticação e chat iniciados.\n"
                                          f"Compartilhe o seguinte IP com os clientes:\n"
                                          f"{ips_str}\n"
                                          f"Porta de Autenticação: {self.main_window.auth_port}\n"
                                          f"Porta de Comunicação: {self.main_window.comm_port}")
        else:
            self.show_error("Erro", "Não foi possível obter o IP local. Verifique sua conexão de rede.")
            print("[ERROR] [AppService] Não foi possível obter o IP local.")
            ips_locais = ['127.0.0.1'] 

        with authenticated_ips_lock:
            for ip in ips_locais:
                authenticated_ips.add(ip)

        self.chat_server_thread = threading.Thread(
            target=start_server,
            args=(self.main_window.chat_widget_instance, self.main_window.comm_port,
                  host_ed25519_private_key, self.dos_detector),
            daemon=True,
            name="ChatServerThread"
        )
        self.chat_server_thread.start()
        self.main_window.show_chat_page()

    def handle_join_clicked(self, username: str, client_password: str, client_ed25519_public_key_bytes: bytes):
        join_dialog = JoinOptionDialog(self.main_window)
        if join_dialog.exec() == QDialog.Accepted:
            server_ip_to_use = None

            if join_dialog.use_gateway:
                server_ip_to_use = obter_gateway()
                print(f"[INFO] [AppService] Tentando usar gateway: {server_ip_to_use}")
            else:
                server_ip_to_use = join_dialog.server_ip
                print(f"[INFO] [AppService] Usando IP fornecido: {server_ip_to_use}")

            if not server_ip_to_use or not self.server_ip_to_validate(server_ip_to_use):
                self.show_error("Erro de IP", "Endereço IP do servidor inválido ou não encontrado.")
                print(f"[ERROR] [AppService] Endereço IP inválido ou não encontrado: {server_ip_to_use}")
                return

            if verificar_conexao_com_host(server_ip_to_use, self.main_window.auth_port, client_password):
                # Pass the main_window instance to join_hotspot_chat for signal connections
                self.join_hotspot_chat(server_ip_to_use, username, client_ed25519_public_key_bytes)
            else:
                self.show_error("Falha na Autenticação", f"Não foi possível autenticar com {server_ip_to_use}. Verifique a senha e o IP.")
                print(f"[ERROR] [AppService] Falha na autenticação com {server_ip_to_use}.")
        else:
            self.show_dialog("Aviso", "Operação de junção à rede cancelada.")

    def server_ip_to_validate(self, ip):
        """Valida formato do IP"""
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            print(f"[ERROR] [AppService] Formato de IP inválido: {ip}")
            return False

    def join_hotspot_chat(self, server_ip: str, username: str, client_ed25519_public_key_bytes: bytes):
        self.disconnect_chat_client() 

        self.main_window.setup_chat_widget(is_host=False)

        self.chat_client_instance = ChatClient(
            server_ip,
            self.main_window.comm_port,
            self.main_window.chat_widget_instance,
            username,
            self.ecc_manager, 
            client_ed25519_public_key_bytes 
        )
        self.main_window.chat_widget_instance.client = self.chat_client_instance

        # --- CORREÇÃO AQUI: Conectar os sinais do worker aos slots da MainWindow ---
        # O ChatClient.connect() agora retorna True/False e cria o worker e thread.
        # Conectamos os sinais do worker AQUI, após o ChatClient.connect() ter sido chamado
        # e o worker ter sido criado.
        
        # Call connect() and check its return value
        connection_successful = self.chat_client_instance.connect() 

        if connection_successful:
            # Now that worker is guaranteed to exist if connection_successful is True
            if self.chat_client_instance.worker:
                self.chat_client_instance.worker.disconnected.connect(self.main_window.on_chat_disconnected)
                self.chat_client_instance.worker.specific_error.connect(self.main_window.handle_specific_chat_error)
            
            self.is_connected_to_chat = True
            self.main_window.show_chat_page()
        else:
            self.show_error("Erro de Conexão", "Não foi possível conectar ao servidor de chat. Verifique se o host está ativo e as portas estão corretas.")
            self.is_connected_to_chat = False
            self.main_window.show_home_page()
            print("[ERROR] [AppService] Falha ao conectar ao chat. Conexão não estabelecida.")


    def disconnect_chat_client(self):
        if self.chat_client_instance:
            if self.chat_client_instance.worker:
                # Disconnect signals to prevent issues if the widget is deleted
                try:
                    self.chat_client_instance.worker.message_received.disconnect(self.main_window.chat_widget_instance.add_message_to_chat)
                except TypeError: pass 
                try:
                    self.chat_client_instance.worker.connection_error.disconnect(self.main_window.chat_widget_instance.add_message_to_chat)
                except TypeError: pass
                try:
                    self.chat_client_instance.worker.disconnected.disconnect(self.main_window.on_chat_disconnected)
                except TypeError: pass
                try:
                    self.chat_client_instance.worker.specific_error.disconnect(self.main_window.handle_specific_chat_error)
                except TypeError: pass
                
                self.chat_client_instance.worker.stop()
                self.chat_client_instance.worker = None
            self.chat_client_instance.disconnect()
            self.chat_client_instance = None
            print("[INFO] [AppService] Cliente de chat desconectado e recursos liberados.")

    def shutdown(self):
        self.auth_service.stop_server()
        stop_chat_server() 
        if self.chat_server_thread and self.chat_server_thread.is_alive():
            self.chat_server_thread.join(timeout=2) 
            if self.chat_server_thread.is_alive():
                print("[WARNING] [AppService] Thread do servidor de chat não encerrou em tempo.")
        
        self.disconnect_chat_client()
        self.dos_detector.stop()
        print("[INFO] [AppService] Shutdown de serviços concluído.")

        with authenticated_ips_lock:
            authenticated_ips.clear()
        with temp_rsa_managers_lock:
            for ip in list(temp_rsa_managers.keys()):
                if ip in temp_rsa_managers:
                    temp_rsa_managers[ip]["manager"].clear_keys()
                    del temp_rsa_managers[ip]
        with connected_users_lock:
            connected_users.clear()

