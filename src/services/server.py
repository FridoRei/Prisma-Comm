import socket
import threading
import time
from src.core.auth.token_manager import verificar_senha
from src.core.chat.globals import authenticated_ips, authenticated_ips_lock, temp_rsa_managers, temp_rsa_managers_lock
from src.core.auth.rsa_manager import RSAManager
import datetime
from src.core.network.dos_detector import DoSDetector

RSA_KEY_LIFETIME_SECONDS = 10 

def handle_public_key_request(conn: socket.socket, addr: tuple, dos_detector: DoSDetector):
    client_ip = addr[0]
    if not dos_detector.check_and_record(client_ip):
        print(f"[WARNING] [AuthServer] Requisição de chave pública de {addr} bloqueada por DoSDetector.")
        try:
            conn.close()
        except Exception as e:
            print(f"[ERROR] [AuthServer] Erro ao fechar conexão bloqueada por DoS")
        return
    try:
        with authenticated_ips_lock:
            if client_ip in authenticated_ips:
                print(f"[WARNING] [AuthServer] Requisição de chave pública de {addr} recusada: cliente já autenticado.")
                conn.sendall(b"CONNECTION_REFUSED\n")
                return

        print(f"[INFO] [AuthServer] Recebida requisição de chave pública de {addr}.")

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
                print(f"[DEBUG] [AuthServer] Chave RSA temporária armazenada para {client_ip}.")
        else:
            conn.sendall(b"ERROR: Public key not available")
            print(f"[ERROR] [AuthServer] Erro: Chave pública RSA não disponível para {addr} após geração.")
    except Exception as e:
        print(f"[ERROR] [AuthServer] Erro ao enviar chave pública para {addr}: {e}")
    finally:
        try:
            conn.close()
            print(f"[DEBUG] [AuthServer] Conexão TCP com {addr} fechada.")
        except Exception as e:
            print(f"[ERROR] [AuthServer] Erro ao fechar conexão TCP com {addr}: {e}")

def run_auth_server(auth_port: int, stop_event: threading.Event, host_password: str, dos_detector: DoSDetector):
    udp_server_socket = None
    tcp_server_socket = None
    try:
        udp_server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_server_socket.bind(('0.0.0.0', auth_port))
        udp_server_socket.settimeout(1.0) 
        tcp_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp_server_socket.bind(('0.0.0.0', auth_port))
        tcp_server_socket.listen(1) 
        tcp_server_socket.settimeout(1.0)

        while not stop_event.is_set():
            with temp_rsa_managers_lock:
                keys_to_remove = []
                for ip, data in temp_rsa_managers.items():
                    if datetime.datetime.now() - data["timestamp"] > datetime.timedelta(seconds=RSA_KEY_LIFETIME_SECONDS):
                        keys_to_remove.append(ip)
                for ip in keys_to_remove:
                    if ip in temp_rsa_managers:
                        temp_rsa_managers[ip]["manager"].clear_keys()
                        del temp_rsa_managers[ip]
                        print(f"[INFO] [AuthServer] Chave RSA temporária para {ip} expirada e removida.")

            try:
                tcp_conn, tcp_addr = tcp_server_socket.accept()
                threading.Thread(target=handle_public_key_request, args=(tcp_conn, tcp_addr, dos_detector), daemon=True).start()
            except socket.timeout:
                pass 
            except OSError as e:
                if stop_event.is_set(): 
                    print(f"[INFO] [AuthServer] Socket TCP fechado durante accept() enquanto o servidor estava parando.")
                else:
                    print(f"[ERROR] [AuthServer] Erro de sistema operacional ao aceitar conexão TCP: {e}")
            except Exception as e:
                print(f"[ERROR] [AuthServer] Erro inesperado ao aceitar conexão TCP: {e}")
            try:
                encrypted_password_hash_from_client, addr = udp_server_socket.recvfrom(256)
                client_ip = addr[0]
                if not dos_detector.check_and_record(client_ip):
                    print(f"[WARNING] [AuthServer] Tentativa de autenticação de {addr} bloqueada por DoSDetector.")
                    with temp_rsa_managers_lock:
                        if client_ip in temp_rsa_managers:
                            temp_rsa_managers[client_ip]["manager"].clear_keys()
                            del temp_rsa_managers[client_ip]
                    continue                

                with authenticated_ips_lock:
                    if client_ip in authenticated_ips:
                        print(f"[WARNING] [AuthServer] Cliente {client_ip} já autenticado. Recusando nova tentativa de autenticação.")
                        udp_server_socket.sendto(b"CONNECTION_REFUSED", addr)
                        with temp_rsa_managers_lock:
                            if client_ip in temp_rsa_managers:
                                temp_rsa_managers[client_ip]["manager"].clear_keys()
                                del temp_rsa_managers[client_ip]
                        continue

                current_rsa_manager_data = None
                with temp_rsa_managers_lock:
                    current_rsa_manager_data = temp_rsa_managers.get(client_ip)

                if not current_rsa_manager_data:
                    print(f"[WARNING] [AuthServer] Nenhuma chave RSA temporária encontrada para {client_ip} (ou expirou). Autenticação falhou.")
                    udp_server_socket.sendto(b"AUTH_FAILURE", addr)
                    continue

                current_rsa_manager = current_rsa_manager_data["manager"]

                try:
                    decrypted_client_password_hash = current_rsa_manager.decrypt_string(encrypted_password_hash_from_client)
                    if verificar_senha(host_password, decrypted_client_password_hash):
                        with authenticated_ips_lock:
                            authenticated_ips.add(client_ip)
                        udp_server_socket.sendto(b"AUTH_SUCCESS", addr)
                        print(f"[SUCCESS] [AuthServer] Autenticação BEM-SUCEDIDA para {client_ip}.")
                    else:
                        udp_server_socket.sendto(b"AUTH_FAILURE", addr)
                        print(f"[WARNING] [AuthServer] Autenticação FALHOU para {client_ip} (senha incorreta).")
                except Exception as e:
                    print(f"[ERROR] [AuthServer] Erro ao descriptografar/verificar senha de {client_ip}: {e}. Dados recebidos podem estar corrompidos.")
                    udp_server_socket.sendto(b"AUTH_FAILURE", addr)
                finally:
                    with temp_rsa_managers_lock:
                        if client_ip in temp_rsa_managers:
                            temp_rsa_managers[client_ip]["manager"].clear_keys()
                            del temp_rsa_managers[client_ip]
                            print(f"[DEBUG] [AuthServer] Chave RSA temporária para {client_ip} removida após autenticação.")

            except socket.timeout:
                pass 
            except Exception as e:
                print(f"[CRITICAL] [AuthServer] Erro inesperado no servidor UDP: {e}")
                if 'client_ip' in locals() and client_ip in temp_rsa_managers:
                    with temp_rsa_managers_lock:
                        temp_rsa_managers[client_ip]["manager"].clear_keys()
                        del temp_rsa_managers[client_ip]
                break 

    finally:
        if udp_server_socket:
            udp_server_socket.close()
            print("[INFO] [AuthServer] Socket UDP do servidor de autenticação fechado.")
        if tcp_server_socket:
            tcp_server_socket.close()
            print("[INFO] [AuthServer] Socket TCP do servidor de autenticação fechado.")
        print("[INFO] [AuthServer] Servidor de autenticação encerrado.")

