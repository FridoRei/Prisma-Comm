import socket
import threading
import time
from src.core.auth.token_manager import verificar_senha
from src.core.chat.globals import temp_rsa_managers, temp_rsa_managers_lock, authenticated_ips, authenticated_ips_lock
from src.core.auth.rsa_manager import RSAManager
import datetime
from src.core.network.dos_detector import DoSDetector
from src.core.network.request_limiter import RequestLimiter
import uuid 

RSA_KEY_LIFETIME_SECONDS = 10
RSA_MAX_SIMULTANEOUS_KEYS = 20
REQUEST_MAX_LENGTH = 600


def handle_public_key_request(conn: socket.socket, addr: tuple, dos_detector: DoSDetector, request_limiter: RequestLimiter):
    client_ip = addr[0]
    if not dos_detector.check_and_record(client_ip):
        print(f"[WARNING] [AuthServer] Requisição de chave pública de {addr} bloqueada por DoSDetector.")
        conn.sendall(b"REFUSED\n")
        conn.close()
        return

    try:
        print(f"[INFO] [AuthServer] Recebida requisição de chave pública de {addr}.")

        current_rsa_manager = RSAManager()
        current_rsa_manager.generate_temp_keys()
        public_key_bytes = current_rsa_manager.get_public_key_bytes()

        if public_key_bytes:
            conn.sendall(public_key_bytes)
            print(f"[INFO] [AuthServer] Chave pública RSA enviada para {addr}.")

            with temp_rsa_managers_lock:
                if len(temp_rsa_managers) >= RSA_MAX_SIMULTANEOUS_KEYS:
                    oldest_ip = None
                    oldest_timestamp = datetime.datetime.now()
                    for ip, data in temp_rsa_managers.items():
                        if data["timestamp"] < oldest_timestamp:
                            oldest_timestamp = data["timestamp"]
                            oldest_ip = ip
                    if oldest_ip:
                        temp_rsa_managers[oldest_ip]["manager"].clear_keys()
                        del temp_rsa_managers[oldest_ip]
                        print(f"[INFO] [AuthServer] Chave RSA temporária mais antiga de {oldest_ip} removida para abrir espaço.")

                temp_rsa_managers[client_ip] = {
                    "manager": current_rsa_manager,
                    "timestamp": datetime.datetime.now()
                }
        else:
            conn.sendall(b"ERROR: Public key not available")
            print(f"[ERROR] [AuthServer] Erro: Chave pública RSA não disponível para {addr} após geração.")
    except Exception as e:
        print(f"[ERROR] [AuthServer] Erro ao enviar chave pública para {addr}: {e}")
    finally:
        try:
            conn.close()
        except Exception as e:
            print(f"[ERROR] [AuthServer] Erro ao fechar conexão TCP com {addr}: {e}")

def run_auth_server(auth_port: int, stop_event: threading.Event, host_password: str, dos_detector: DoSDetector, host_udp_operation_timeout: int):
    udp_server_socket = None
    tcp_server_socket = None
    request_limiter = RequestLimiter(max_length=REQUEST_MAX_LENGTH)

    try:
        udp_server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_server_socket.bind(('0.0.0.0', auth_port))
        udp_server_socket.settimeout(host_udp_operation_timeout)
        tcp_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp_server_socket.bind(('0.0.0.0', auth_port))
        tcp_server_socket.listen(5)
        tcp_server_socket.settimeout(1.0)

        print(f"[INFO] [AuthServer] Servidor de autenticação iniciado na porta {auth_port}.")

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

            try:
                tcp_conn, tcp_addr = tcp_server_socket.accept()
                threading.Thread(target=handle_public_key_request, args=(tcp_conn, tcp_addr, dos_detector, request_limiter), daemon=True).start()
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
                encrypted_password_hash_from_client, addr = udp_server_socket.recvfrom(4096)
                client_ip = addr[0]

                if request_limiter.is_request_too_large(encrypted_password_hash_from_client):
                    print(f"[WARNING] [AuthServer] Requisição UDP de {addr} excedeu o limite de tamanho. Descartando.")
                    udp_server_socket.sendto(b"REQUEST_TOO_LARGE", addr)
                    with temp_rsa_managers_lock:
                        if client_ip in temp_rsa_managers:
                            temp_rsa_managers[client_ip]["manager"].clear_keys()
                            del temp_rsa_managers[client_ip]
                    continue

                if not dos_detector.check_and_record(client_ip):
                    print(f"[WARNING] [AuthServer] Tentativa de autenticação de {addr} bloqueada por DoSDetector.")
                    udp_server_socket.sendto(b"REFUSED", addr)
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
        stop_event.set()

        if udp_server_socket:
            udp_server_socket.close()
            print("[INFO] [AuthServer] Socket UDP do servidor de autenticação fechado.")
        if tcp_server_socket:
            tcp_server_socket.close()
            print("[INFO] [AuthServer] Socket TCP do servidor de autenticação fechado.")
        print("[INFO] [AuthServer] Servidor de autenticação encerrado.")


