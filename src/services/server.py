import socket
import threading
import time
from src.core.auth.token_manager import validar_token
from src.core.chat.globals import authenticated_ips, authenticated_ips_lock, temp_rsa_managers, temp_rsa_managers_lock
from src.core.auth.rsa_manager import RSAManager
import datetime 

RSA_KEY_LIFETIME_SECONDS = 10

def handle_public_key_request(conn, addr):
    client_ip = addr[0]
    try:
        with authenticated_ips_lock:
            if client_ip in authenticated_ips:
                conn.sendall(b"CONNECTION_REFUSED\n")
                return
            
        print(f"[AuthServer] Requisição de chave pública de {addr}")

        current_rsa_manager = RSAManager()
        current_rsa_manager.generate_temp_keys()

        public_key_bytes = current_rsa_manager.get_public_key_bytes()

        if public_key_bytes:
            conn.sendall(public_key_bytes)

            with temp_rsa_managers_lock:
                temp_rsa_managers[client_ip] = {
                    "manager": current_rsa_manager,
                    "timestamp": datetime.datetime.now()
                }
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
        with temp_rsa_managers_lock:
            keys_to_remove = []
            for ip, data in temp_rsa_managers.items():
                if datetime.datetime.now() - data["timestamp"] > datetime.timedelta(seconds=RSA_KEY_LIFETIME_SECONDS):
                    keys_to_remove.append(ip)
            for ip in keys_to_remove:
                del temp_rsa_managers[ip]
                print(f"[AuthServer] Chave RSA temporária para {ip} expirada e removida.")

        try:
            tcp_conn, tcp_addr = tcp_server_socket.accept()
            threading.Thread(target=handle_public_key_request, args=(tcp_conn, tcp_addr), daemon=True).start()
        except socket.timeout:
            pass 

        try:
            encrypted_token, addr = udp_server_socket.recvfrom(256)
            client_ip = addr[0]

            with authenticated_ips_lock:
                if client_ip in authenticated_ips:
                    udp_server_socket.sendto(b"CONNECTION_REFUSED\n")
                    with temp_rsa_managers_lock:
                        if client_ip in temp_rsa_managers:
                            temp_rsa_managers[client_ip]["manager"].clear_keys()
                            del temp_rsa_managers[client_ip]
                    continue

            current_rsa_manager_data = None
            with temp_rsa_managers_lock:
                current_rsa_manager_data = temp_rsa_managers.get(client_ip)

            if not current_rsa_manager_data:
                print(f"[AuthServer] Erro: Nenhuma chave RSA temporária encontrada para {client_ip} (ou expirou). Autenticação falhou.")
                udp_server_socket.sendto(b"AUTH_FAILURE", addr)
                continue 

            current_rsa_manager = current_rsa_manager_data["manager"]

            try:
                token = current_rsa_manager.decrypt_string(encrypted_token)
                if validar_token(token):
                    with authenticated_ips_lock:
                        authenticated_ips.add(client_ip)
                    udp_server_socket.sendto(b"AUTH_SUCCESS", addr)
                    print(f"[AuthServer] Autenticação BEM-SUCEDIDA para {client_ip}")
                else:
                    udp_server_socket.sendto(b"AUTH_FAILURE", addr)
                    print(f"[AuthServer] Autenticação FALHOU para {client_ip}")
            except Exception as e:
                print(f"[AuthServer] Erro ao descriptografar/validar token de {client_ip}: {e}")
                udp_server_socket.sendto(b"AUTH_FAILURE", addr)
            finally:
                with temp_rsa_managers_lock:
                    if client_ip in temp_rsa_managers:
                        temp_rsa_managers[client_ip]["manager"].clear_keys() 
                        del temp_rsa_managers[client_ip] 

        except socket.timeout:
            pass 
        except Exception as e:
            print(f"[AuthServer] Erro no servidor UDP: {e}")
            if client_ip in temp_rsa_managers:
                with temp_rsa_managers_lock:
                    temp_rsa_managers[client_ip]["manager"].clear_keys()
                    del temp_rsa_managers[client_ip]
            break 

    udp_server_socket.close()
    tcp_server_socket.close()
    print("[AuthServer] Servidor de autenticação encerrado.")
