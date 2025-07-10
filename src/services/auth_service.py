import subprocess
import os
import signal
import sys
from src.config.settings import DEFAULT_AUTH_PORT 

class AuthService:
    def __init__(self, auth_port=DEFAULT_AUTH_PORT):
        self.auth_port = auth_port
        self.auth_server_process = None

    def start_server(self):
        if self.auth_server_process and self.auth_server_process.poll() is None:
            print("[P2P-COM] Servidor de autenticação já está rodando.")
            return

        try:
            server_script_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'server.py'))

            self.auth_server_process = subprocess.Popen(
                [sys.executable, server_script_path, str(self.auth_port)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=os.setsid
            )
            print(f"[P2P-COM] Servidor de autenticação iniciado em segundo plano na porta {self.auth_port}.")

        except Exception as e:
            print(f"[P2P-COM] Erro ao iniciar servidor de autenticação: {e}")
            raise 

    def stop_server(self):
        if self.auth_server_process and self.auth_server_process.poll() is None:
            try:
                os.killpg(os.getpgid(self.auth_server_process.pid), signal.SIGTERM)
                self.auth_server_process.wait(timeout=5)
                print("[P2P-COM] Servidor de autenticação encerrado.")
            except Exception as e:
                print(f"[P2P-COM] Erro ao encerrar servidor de autenticação: {e}")
        self.auth_server_process = None

