import os
import subprocess
import signal
import sys
import time
from src.config.settings import DEFAULT_AUTH_PORT

class AuthService:
    def __init__(self, auth_port=DEFAULT_AUTH_PORT):
        self.auth_port = auth_port
        self.auth_server_process = None

    def start_server(self):
        if self.auth_server_process and self.auth_server_process.poll() is None:
            print("[AUTH_SERVICE] Servidor de autenticação já está rodando.")
            return
            
        try:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            server_script_path = os.path.join(current_dir, 'server.py')
            
            if not os.path.exists(server_script_path):
                raise FileNotFoundError(f"O script do servidor 'server.py' não foi encontrado em: {server_script_path}")

            print(f"[AUTH_SERVICE] Tentando iniciar o script do servidor: {server_script_path}")
            
            self.auth_server_process = subprocess.Popen(
                [sys.executable, '-m', 'src.services.server', str(self.auth_port)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=os.setsid,
                cwd=os.path.dirname(os.path.dirname(current_dir))  
            )
            
            time.sleep(0.5)
            
            if self.auth_server_process.poll() is not None:
                stdout_data, stderr_data = self.auth_server_process.communicate()
                if stderr_data:
                    print(f"[AUTH_SERVICE] ERRO DE INICIALIZAÇÃO DO SERVIDOR (stderr): {stderr_data.decode().strip()}")
                if stdout_data:
                    print(f"[AUTH_SERVICE] SAÍDA DE INICIALIZAÇÃO DO SERVIDOR (stdout): {stdout_data.decode().strip()}")
                raise RuntimeError("Servidor de autenticação falhou ao iniciar.")
                
            print(f"[AUTH_SERVICE] Servidor de autenticação iniciado em segundo plano na porta {self.auth_port}")

        except FileNotFoundError as e:
            print(f"[AUTH_SERVICE] ERRO: {e}")
            self.auth_server_process = None
            raise
        except Exception as e:
            print(f"[AUTH_SERVICE] Erro ao iniciar servidor de autenticação: {e}")
            if self.auth_server_process and self.auth_server_process.poll() is None:
                try:
                    os.killpg(os.getpgid(self.auth_server_process.pid), signal.SIGTERM)
                except Exception as kill_e:
                    print(f"[AUTH_SERVICE] Erro ao tentar encerrar processo falho: {kill_e}")
            self.auth_server_process = None
            raise

    def stop_server(self):
        if self.auth_server_process and self.auth_server_process.poll() is None:
            try:
                os.killpg(os.getpgid(self.auth_server_process.pid), signal.SIGTERM)
                self.auth_server_process.wait(timeout=5)
                print("[AUTH_SERVICE] Servidor de autenticação encerrado.")
            except Exception as e:
                print(f"[AUTH_SERVICE] Erro ao encerrar servidor de autenticação: {e}")
        self.auth_server_process = None

    def is_running(self):
        return self.auth_server_process is not None and self.auth_server_process.poll() is None
