import threading
from PySide6.QtWidgets import QMessageBox, QDialog
from src.core.network.connection_manager import obter_gateway, obter_gateway_generico, perform_ecc_auth_handshake
from src.core.chat.chat_client import ChatClient
from src.core.chat.chat_server import start_server, stop_chat_server
from src.services.auth_service import AuthService
from src.config.settings import DEFAULT_USERNAME, DEFAULT_AUTH_PORT, DEFAULT_COMM_PORT, DEFAULT_CLIENT_ECC_HANDSHAKE_TIMEOUT
from src.core.chat.globals import connected_users, connected_users_lock
import socket
from src.core.crypto.ecc_manager import ECCManager
from cryptography.hazmat.primitives.asymmetric import ed25519
from src.core.network.dos_detector import DoSDetector

class AppService:
    def __init__(self, main_window_instance, original_stdout, original_stderr, ecc_manager, timeout_settings: dict):
        self.main_window = main_window_instance
        self.timeout_settings = timeout_settings
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

    def update_timeout_settings(self, new_timeout_settings: dict):
        """
        Atualiza as configurações de timeout da aplicação.
        """
        self.timeout_settings.update(new_timeout_settings)

    def handle_host_clicked(self, host_password: str, host_ed25519_private_key: ed25519.Ed25519PrivateKey):
        try:
            self.auth_service.start_server(host_password, host_ed25519_private_key)
        except Exception as e:
            self.show_error("Erro ao Iniciar Servidor", "Não foi possível iniciar o servidor de autenticação. Verifique as configurações e tente novamente.") 
            return

        self.main_window.setup_chat_widget(is_host=True)
        self.is_connected_to_chat = True
        
        self.main_window.chat_widget_instance.request_host_shutdown.connect(self.shutdown_host)        

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

        self.chat_server_thread = threading.Thread(
            target=start_server,
            args=(self.main_window.chat_widget_instance, self.main_window.comm_port, self.dos_detector, self.timeout_settings['host_client_data_receive_timeout']),
            daemon=True,
            name="ChatServerThread"
        )
        self.chat_server_thread.start()
        self.main_window.show_chat_page()

    def handle_join_clicked(self, username: str, client_password: str, client_ed25519_public_key_bytes: bytes, server_ip_from_dialog: str = None, use_gateway_from_dialog: bool = False):
        server_ip_to_use = None

        if use_gateway_from_dialog:
            server_ip_to_use = obter_gateway()
            print(f"[INFO] [AppService] Tentando usar gateway: {server_ip_to_use}")
        else:
            server_ip_to_use = server_ip_from_dialog
            print(f"[INFO] [AppService] Usando IP fornecido: {server_ip_to_use}")

        if not server_ip_to_use or not self.server_ip_to_validate(server_ip_to_use):
            self.show_error("Erro de Conexão", "Endereço IP do servidor inválido ou não encontrado.")
            print(f"[ERROR] [AppService] Endereço IP inválido ou não encontrado: {server_ip_to_use}")
            return

        auth_result, session_aes_key = perform_ecc_auth_handshake(
            server_ip_to_use,
            self.main_window.auth_port,
            client_password,
            client_ed25519_public_key_bytes,
            self.ecc_manager, 
            self.timeout_settings.get('client_ecc_handshake_timeout'),
            self.timeout_settings['client_password_response_timeout']
        )

        if auth_result == "AUTH_SUCCESS":
            self.join_hotspot_chat(server_ip_to_use, username, session_aes_key)
        else:
            self.show_error("Falha na Autenticação", f"Não foi possível autenticar com o host: {auth_result}. Verifique a senha e o IP e tente novamente.")
            print(f"[ERROR] [AppService] Falha na autenticação com {server_ip_to_use}: {auth_result}.")



    def server_ip_to_validate(self, ip):
        """Valida formato do IP"""
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            print(f"[ERROR] [AppService] Formato de IP inválido: {ip}")
            return False

    def join_hotspot_chat(self, server_ip: str, username: str, session_aes_key: bytes):
        self.disconnect_chat_client()

        self.main_window.setup_chat_widget(is_host=False)

        self.chat_client_instance = ChatClient(
            server_ip,
            self.main_window.comm_port,
            self.main_window.chat_widget_instance,
            username,
            self.ecc_manager,
            session_aes_key,
            self.timeout_settings['client_message_receive_timeout'],
            self.timeout_settings['client_handshake_timeout']
        )
        self.main_window.chat_widget_instance.client = self.chat_client_instance
        
        self.main_window.chat_widget_instance.request_client_disconnect.connect(self.disconnect_chat_client)
        
        connection_successful = self.chat_client_instance.connect()

        if connection_successful:
            if self.chat_client_instance.worker:
                if self.main_window.chat_widget_instance:
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
        """
        Desconecta o cliente do chat e limpa os recursos.
        Este método pode ser chamado tanto internamente (ex: erro de conexão)
        quanto externamente (ex: botão de desconexão).
        """
        if self.chat_client_instance:
            print("[INFO] [AppService] Desconectando cliente de chat...")
            if self.chat_client_instance.worker:
                if self.main_window.chat_widget_instance:
                    try:
                        self.chat_client_instance.worker.message_received.disconnect(self.main_window.chat_widget_instance.add_message_to_chat)
                    except (TypeError, RuntimeError) as e:
                        print(f"[DEBUG] [AppService] Erro ao desconectar message_received (pode ser normal): {e}")
                    try:
                        self.chat_client_instance.worker.connection_error.disconnect(self.main_window.chat_widget_instance.add_message_to_chat)
                    except (TypeError, RuntimeError) as e:
                        print(f"[DEBUG] [AppService] Erro ao desconectar connection_error (pode ser normal): {e}")
                    try:
                        self.chat_client_instance.worker.disconnected.disconnect(self.main_window.on_chat_disconnected)
                    except (TypeError, RuntimeError) as e:
                        print(f"[DEBUG] [AppService] Erro ao desconectar disconnected (pode ser normal): {e}")
                    try:
                        self.chat_client_instance.worker.specific_error.disconnect(self.main_window.handle_specific_chat_error)
                    except (TypeError, RuntimeError) as e:
                        print(f"[DEBUG] [AppService] Erro ao desconectar specific_error (pode ser normal): {e}")
                    try:
                        self.main_window.chat_widget_instance.request_client_disconnect.disconnect(self.disconnect_chat_client)
                    except (TypeError, RuntimeError) as e:
                        print(f"[DEBUG] [AppService] Erro ao desconectar request_client_disconnect (pode ser normal): {e}")

                else:
                    print("[INFO] [AppService] chat_widget_instance já é None, pulando desconexão de sinais específicos do worker.")

                self.chat_client_instance.worker.stop()
                self.chat_client_instance.worker = None
            self.chat_client_instance.disconnect() 
            self.chat_client_instance = None
            self.is_connected_to_chat = False
            self.main_window.on_chat_disconnected() 
        else:
            print("[INFO] [AppService] Nenhuma instância de ChatClient ativa para desconectar.")
   
    def shutdown_host(self):
        """
        Encerra os servidores de autenticação e chat quando o host decide parar.
        Este método é chamado pelo botão "Encerrar Host".
        """
        print("[INFO] [AppService] Solicitando encerramento do host...")
        if self.main_window.chat_widget_instance:
            try:
                self.main_window.chat_widget_instance.request_host_shutdown.disconnect(self.shutdown_host)
            except (TypeError, RuntimeError) as e:
                print(f"[DEBUG] [AppService] Erro ao desconectar request_host_shutdown (pode ser normal): {e}")
        self.shutdown() 
        self.main_window.on_chat_disconnected()
        self.show_dialog("Host Encerrado", "O servidor foi encerrado. Todos os clientes serão desconectados.")   
            
    def shutdown(self):
        self.auth_service.stop_server()
        stop_chat_server()
        if self.chat_server_thread and self.chat_server_thread.is_alive():
            self.chat_server_thread.join(timeout=2)
            if self.chat_server_thread.is_alive():
                print("[WARNING] [AppService] Thread do servidor de chat não encerrou em tempo.")

        self.disconnect_chat_client()
        self.dos_detector.stop()

        with connected_users_lock:
            connected_users.clear()
