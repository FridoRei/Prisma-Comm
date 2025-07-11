import socket
import threading
import time
from src.core.auth.token_manager import validar_token
from src.core.chat.globals import authenticated_ips, authenticated_ips_lock

def run_auth_server(auth_port, stop_event):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.settimeout(1.0)  
    
    try:
        server_socket.bind(('0.0.0.0', auth_port))
        server_socket.listen(5)
        print(f"[AuthServer] Servidor de autenticação iniciado na porta {auth_port}")

        while not stop_event.is_set():
            try:
                conn, addr = server_socket.accept()
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
            except Exception as e:
                print(f"[AuthServer] Erro durante conexão: {str(e)}")
                if 'conn' in locals():
                    conn.close()

    except Exception as e:
        print(f"[AuthServer] Erro fatal: {str(e)}")
    finally:
        server_socket.close()
        print("[AuthServer] Servidor encerrado")
