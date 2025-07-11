import socket
import threading
import time
import ssl # Adicionar import
from src.core.auth.token_manager import validar_token
from src.core.chat.globals import authenticated_ips, authenticated_ips_lock
from src.config.settings import SERVER_CERT, SERVER_KEY # Adicionar import

def run_auth_server(auth_port, stop_event):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.settimeout(1.0)

    # Configuração SSL para o servidor de autenticação
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=SERVER_CERT, keyfile=SERVER_KEY)
    context.verify_mode = ssl.CERT_NONE # Não verificar certificado do cliente para autenticação, apenas token

    try:
        server_socket.bind(('0.0.0.0', auth_port))
        server_socket.listen(5)

        # Envolver o socket do servidor com TLS
        ssl_server_socket = context.wrap_socket(server_socket, server_side=True)

        print(f"[AuthServer] Servidor de autenticação iniciado na porta {auth_port} (TLS/SSL)")

        while not stop_event.is_set():
            try:
                conn, addr = ssl_server_socket.accept() # Aceitar conexão TLS
                client_ip = addr[0]

                token_recebido = conn.recv(1024).decode('utf-8').strip()
                if not token_recebido:
                    conn.close()
                    continue

                if validar_token(token_recebido, addr):
                    with authenticated_ips_lock:
                        authenticated_ips.add(client_ip)
                    print(f"[AuthServer] IP {client_ip} autenticado. Lista atual: {authenticated_ips}")
                    resposta = "AUTH_SUCCESS"
                else:
                    print("[AuthServer] Token inválido")
                    resposta = "AUTH_FAILURE"

                conn.sendall(resposta.encode('utf-8'))
                conn.close()

            except socket.timeout:
                continue
            except ssl.SSLError as e: # Capturar erros SSL durante a aceitação
                print(f"[AuthServer] Erro SSL durante conexão: {e}")
                if 'conn' in locals():
                    conn.close()
            except Exception as e:
                print(f"[AuthServer] Erro durante conexão: {str(e)}")
                if 'conn' in locals():
                    conn.close()

    except Exception as e:
        print(f"[AuthServer] Erro fatal: {str(e)}")
    finally:
        if 'ssl_server_socket' in locals() and ssl_server_socket:
            ssl_server_socket.close()
        server_socket.close()
        print("[AuthServer] Servidor encerrado")
