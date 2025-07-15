import threading
from src.services.server import run_auth_server
from src.core.network.dos_detector import DoSDetector

class AuthService:
    def __init__(self, auth_port: int, dos_detector: DoSDetector): 
        self.auth_port = auth_port
        self.dos_detector = dos_detector 
        self.stop_event = threading.Event()
        self.server_thread = None
        self.host_password = None 

    def start_server(self, host_password: str):
        self.host_password = host_password       
        if self.server_thread and self.server_thread.is_alive():
            print("[INFO] [AuthService] Servidor de autenticação já está rodando.")
            return

        self.stop_event.clear()
        self.server_thread = threading.Thread(
            target=run_auth_server,
            args=(self.auth_port, self.stop_event, self.host_password, self.dos_detector),
            daemon=True,
            name="AuthServerThread" 
        )
        self.server_thread.start()
        print(f"[INFO] [AuthService] Servidor de autenticação iniciado na porta {self.auth_port}.")

    def stop_server(self):
        if self.server_thread and self.server_thread.is_alive():
            print("[INFO] [AuthService] Sinalizando para o servidor de autenticação parar...")
            self.stop_event.set()
            self.server_thread.join(timeout=2) 
            if self.server_thread.is_alive():
                print("[WARNING] [AuthService] Servidor de autenticação não encerrou em tempo.")
            else:
                print("[INFO] [AuthService] Servidor de autenticação encerrado.")
        else:
            print("[INFO] [AuthService] Servidor de autenticação não está rodando ou já parou.")
        self.host_password = None 

