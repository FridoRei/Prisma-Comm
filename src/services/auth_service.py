# File: /wifi-chat v2/src/services/auth_service.py

import os
import subprocess
import signal
import sys
import time
import threading # <-- Adicione esta importação
from src.config.settings import DEFAULT_AUTH_PORT

class AuthService:
    def __init__(self, auth_port=DEFAULT_AUTH_PORT, log_callback=None): # <-- Adicione log_callback
        self.auth_port = auth_port
        self.auth_server_process = None
        self.log_callback = log_callback # <-- Armazena a função de callback para logs

    def _read_pipe_and_emit_log(self, pipe, prefix=""): # <-- Novo método para ler pipes
        """Lê continuamente de um pipe e envia para o callback de log."""
        for line in iter(pipe.readline, b''):
            decoded_line = line.decode(errors='ignore').strip()
            if decoded_line and self.log_callback:
                self.log_callback(f"{prefix}{decoded_line}")
        pipe.close()

    def start_server(self):
        if self.auth_server_process and self.auth_server_process.poll() is None:
            if self.log_callback:
                self.log_callback("[P2P-COM] Servidor de autenticação já está rodando.")
            return
            
        try:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            server_script_path = os.path.join(current_dir, 'server.py')
            
            if not os.path.exists(server_script_path):
                raise FileNotFoundError(f"O script do servidor 'server.py' não foi encontrado em: {server_script_path}")

            if self.log_callback:
                self.log_callback(f"[P2P-COM] Tentando iniciar o script do servidor: {server_script_path}")
            
            self.auth_server_process = subprocess.Popen(
                [sys.executable, '-m', 'src.services.server', str(self.auth_port)],
                stdout=subprocess.PIPE, # <-- Mantenha PIPE
                stderr=subprocess.PIPE, # <-- Mantenha PIPE
                preexec_fn=os.setsid,
                cwd=os.path.dirname(os.path.dirname(current_dir))
            )
            
            # Inicia threads para ler stdout e stderr do subprocesso
            if self.log_callback:
                threading.Thread(target=self._read_pipe_and_emit_log, 
                                 args=(self.auth_server_process.stdout, "[AUTH_SERVER_STDOUT] "), 
                                 daemon=True).start()
                threading.Thread(target=self._read_pipe_and_emit_log, 
                                 args=(self.auth_server_process.stderr, "[AUTH_SERVER_STDERR] "), 
                                 daemon=True).start()

            # Bloco de depuração temporário (se ainda estiver lá, remova-o ou comente-o)
            # time.sleep(0.5)
            # if self.auth_server_process.poll() is not None:
            #     # ... (código de leitura de stdout/stderr e raise RuntimeError) ...
            #     pass # Remova este 'pass' se você tiver o bloco de depuração aqui

            if self.log_callback:
                self.log_callback(f"[P2P-COM] Servidor de autenticação iniciado em segundo plano na porta {self.auth_port}")

        except FileNotFoundError as e:
            if self.log_callback:
                self.log_callback(f"[P2P-COM] ERRO: {e}")
            self.auth_server_process = None
            raise
        except Exception as e:
            if self.log_callback:
                self.log_callback(f"[P2P-COM] Erro ao iniciar servidor de autenticação: {e}")
            if self.auth_server_process and self.auth_server_process.poll() is None:
                try:
                    os.killpg(os.getpgid(self.auth_server_process.pid), signal.SIGTERM)
                except Exception as kill_e:
                    if self.log_callback:
                        self.log_callback(f"[P2P-COM] Erro ao tentar encerrar processo falho: {kill_e}")
            self.auth_server_process = None
            raise

    def stop_server(self):
        if self.auth_server_process and self.auth_server_process.poll() is None:
            try:
                os.killpg(os.getpgid(self.auth_server_process.pid), signal.SIGTERM)
                self.auth_server_process.wait(timeout=5)
                if self.log_callback:
                    self.log_callback("[P2P-COM] Servidor de autenticação encerrado.")
            except Exception as e:
                if self.log_callback:
                    self.log_callback(f"[P2P-COM] Erro ao encerrar servidor de autenticação: {e}")
        self.auth_server_process = None

    def is_running(self):
        return self.auth_server_process is not None and self.auth_server_process.poll() is None
