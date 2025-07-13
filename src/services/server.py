import socket
import threading
import time
from src.core.auth.token_manager import validar_token
from src.core.chat.globals import authenticated_ips, authenticated_ips_lock
from src.core.auth.rsa_manager import RSAManager
rsa_manager_instance = RSAManager()

def handle_public_key_request(conn, addr):
    try:
        print(f"[AuthServer] Requisição de chave pública de {addr}")
        
        rsa_manager_instance.generate_temp_keys()
        
        public_key_bytes = rsa_manager_instance.get_public_key_bytes() 
        
        if public_key_bytes:
            conn.sendall(public_key_bytes)
        else:
            conn.sendall(b"ERROR: Public key not available")
            print(f"[AuthServer] Erro: Chave pública não disponível para {addr}")
    except Exception as e:
        print(f"[AuthServer] Erro ao enviar chave pública para {addr}: {e}")
    finally:
        conn.close()

def run_auth_server(auth_port, stop_event):
    udp_server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_server_socket.bind(('0.0.0.0', auth_port))
    udp_server_socket.settimeout(1.0)

    tcp_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp_server_socket.bind(('0.0.0.0', auth_port))
    tcp_server_socket.listen(1)
    tcp_server_socket.settimeout(1.0)

    print(f"[AuthServer] Servidor de autenticação iniciado na porta {auth_port}")

    while not stop_event.is_set():
        try:
            tcp_conn, tcp_addr = tcp_server_socket.accept()
            threading.Thread(target=handle_public_key_request, args=(tcp_conn, tcp_addr), daemon=True).start()
        except socket.timeout:
            pass

        try:
            encrypted_token, addr = udp_server_socket.recvfrom(256)
            try:
                token = rsa_manager_instance.decrypt_string(encrypted_token)
                if validar_token(token):
                    with authenticated_ips_lock:
                        authenticated_ips.add(addr[0])
                    udp_server_socket.sendto(b"AUTH_SUCCESS", addr)
                    print(f"[AuthServer] Autenticação BEM-SUCEDIDA para {addr[0]}")
                else:
                    udp_server_socket.sendto(b"AUTH_FAILURE", addr)
                    print(f"[AuthServer] Autenticação FALHOU para {addr[0]}")
            except Exception as e:
                print(f"[AuthServer] Erro ao descriptografar/validar token de {addr}: {e}")
                udp_server_socket.sendto(b"AUTH_FAILURE", addr)
            finally:
                rsa_manager_instance.clear_keys()

        except socket.timeout:
            pass
        except Exception as e:
            print(f"[AuthServer] Erro no servidor UDP: {e}")
            break

    udp_server_socket.close()
    tcp_server_socket.close()
    print("[AuthServer] Servidor de autenticação encerrado.")
