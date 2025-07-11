# src/services/auth_service.py (Adaptado)
import threading
import socket
import sys
import time
from src.config.settings import DEFAULT_AUTH_PORT
from src.core.auth.token_manager import validar_token, calcular_palavra_base
from src.core.chat.globals import authenticated_ips, authenticated_ips_lock

class AuthService:
    def __init__(self, auth_port=DEFAULT_AUTH_PORT, original_stdout=sys.stdout, original_stderr=sys.stderr):
        self.auth_port = auth_port
        self.auth_server_thread = None
        self._running = False
        self.server_socket = None
        self.original_stdout = original_stdout
        self.original_stderr = original_stderr

    def _run_server(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.settimeout(1.0) # Para permitir que o loop verifique self._running

        try:
            self.server_socket.bind(('0.0.0.0', self.auth_port))
            self.server_socket.listen(1)
            print(f"[AUTH_SERVICE] Servidor de autenticação escutando em 0.0.0.0:{self.auth_port}")

            while self._running:
                conn = None
                try:
                    conn, addr = self.server_socket.accept()
                    print(f"\n[AUTH_SERVICE] Conexão recebida de {addr}")
                    client_ip = addr[0]
                    resposta = "AUTH_FAILURE"

                    try:
                        token_recebido_bytes = conn.recv(1024)
                        if not token_recebido_bytes:
                            print("[AUTH_SERVICE] Cliente desconectou antes de enviar o token.")
                            continue

                        token_recebido = token_recebido_bytes.decode('utf-8').strip()
                        if validar_token(token_recebido, addr):
                            with authenticated_ips_lock:
                                authenticated_ips.add(client_ip)
                            print(f"[AUTH_SERVICE] IP {client_ip} adicionado à lista de IPs autenticados. Lista atual: {authenticated_ips}")
                            resposta = "AUTH_SUCCESS"
                        else:
                            print("[AUTH_SERVICE] Token INVÁLIDO.")
                            resposta = "AUTH_FAILURE_INVALID_TOKEN"

                    except socket.timeout:
                        print("[AUTH_SERVICE] Timeout ao receber token do cliente.")
                        resposta = "AUTH_FAILURE_TIMEOUT"
                    except Exception as e:
                        print(f"[AUTH_SERVICE] Erro ao processar conexão de autenticação: {e}")
                        resposta = f"AUTH_FAILURE_ERROR: {str(e)}"
                    finally:
                        if conn:
                            conn.sendall(resposta.encode('utf-8'))
                            conn.close()
                            print(f"[AUTH_SERVICE] Resposta enviada ao cliente {addr}: {resposta}")

                except socket.timeout:
                    pass # Timeout é normal, permite que o loop verifique self._running
                except Exception as e:
                    if self._running:
                        print(f"[AUTH_SERVICE] Erro ao aceitar conexão: {e}")

        except Exception as e:
            print(f"[AUTH_SERVICE] Erro fatal no servidor de autenticação: {e}")
        finally:
            if self.server_socket:
                self.server_socket.close()
            print("[AUTH_SERVICE] Servidor de autenticação encerrado.")

    def start_server(self):
        if self._running:
            print("[AUTH_SERVICE] Servidor de autenticação já está rodando.")
            return

        self._running = True
        self.auth_server_thread = threading.Thread(target=self._run_server, daemon=True)
        self.auth_server_thread.start()
        print(f"[AUTH_SERVICE] Servidor de autenticação iniciado em thread na porta {self.auth_port}")

    def stop_server(self):
        if self._running:
            self._running = False
            # Pequeno delay para a thread ter tempo de parar
            time.sleep(0.1)
            # Se o socket estiver bloqueado em accept(), fechar o socket força a saída
            if self.server_socket:
                try:
                    self.server_socket.shutdown(socket.SHUT_RDWR)
                    self.server_socket.close()
                except OSError as e:
                    print(f"[AUTH_SERVICE] Erro ao fechar socket do servidor de autenticação: {e}")
            if self.auth_server_thread and self.auth_server_thread.is_alive():
                self.auth_server_thread.join(timeout=2) # Espera a thread terminar
                if self.auth_server_thread.is_alive():
                    print("[AUTH_SERVICE] Aviso: Thread do servidor de autenticação pode não ter terminado.")
            print("[AUTH_SERVICE] Sinal para encerrar servidor de autenticação enviado.")
        self.auth_server_thread = None

    def is_running(self):
        return self._running and self.auth_server_thread and self.auth_server_thread.is_alive()

