import socket
import threading
import time
from src.core.auth.token_manager import validar_token
from src.core.chat.globals import authenticated_ips, authenticated_ips_lock
from src.core.auth.rsa_manager import RSAManager

# Função para lidar com requisições de chave pública (TCP)
def handle_public_key_request(conn, addr):
    try:
        print(f"[AuthServer] Requisição de chave pública de {addr}")
        
        public_key_obj = RSAManager().get_public_key() 
        
        if public_key_obj:
            public_key_bytes = public_key_obj.export_key() 
            conn.sendall(public_key_bytes)
            print(f"[AuthServer] Chave pública enviada para {addr}")
        else:
            conn.sendall(b"ERROR: Public key not available")
            print(f"[AuthServer] Erro: Chave pública não disponível para {addr}")
    except Exception as e:
        print(f"[AuthServer] Erro ao enviar chave pública para {addr}: {e}")
    finally:
        conn.close() # Garante que a conexão TCP é fechada após o envio

def run_auth_server(auth_port, stop_event):
    # Servidor UDP para autenticação de token
    udp_server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_server_socket.bind(('0.0.0.0', auth_port))
    udp_server_socket.settimeout(1.0) # Timeout para não bloquear indefinidamente

    # Servidor TCP para troca de chave pública
    tcp_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp_server_socket.bind(('0.0.0.0', auth_port))
    tcp_server_socket.listen(1) # Apenas uma conexão TCP por vez para a chave pública
    tcp_server_socket.settimeout(1.0) # Timeout para não bloquear indefinidamente

    print(f"[AuthServer] Servidor de autenticação (UDP) e chave pública (TCP) iniciado na porta {auth_port}")

    while not stop_event.is_set():
        # Lidar com conexões TCP (chave pública)
        try:
            tcp_conn, tcp_addr = tcp_server_socket.accept()
            # Inicia uma nova thread para lidar com a requisição TCP
            threading.Thread(target=handle_public_key_request, args=(tcp_conn, tcp_addr), daemon=True).start()
        except socket.timeout:
            pass # Nenhuma conexão TCP pendente, continue

        # Lidar com datagramas UDP (autenticação de token)
        try:
            encrypted_token, addr = udp_server_socket.recvfrom(256) # Recebe o datagrama UDP
            print(f"[AuthServer] Recebido datagrama UDP de {addr}") # Log para depuração
            try:
                token = RSAManager().decrypt_token(encrypted_token)
                if validar_token(token):
                    with authenticated_ips_lock:
                        authenticated_ips.add(addr[0])
                    udp_server_socket.sendto(b"AUTH_SUCCESS", addr)
                    print(f"[AuthServer] Autenticação BEM-SUCEDIDA para {addr[0]}") # Log de sucesso
                else:
                    udp_server_socket.sendto(b"AUTH_FAILURE", addr)
                    print(f"[AuthServer] Autenticação FALHOU para {addr[0]}") # Log de falha
            except Exception as e:
                print(f"[AuthServer] Erro ao descriptografar/validar token de {addr}: {e}")
                udp_server_socket.sendto(b"AUTH_FAILURE", addr) # Envia falha em caso de erro de descriptografia
        except socket.timeout:
            pass # Nenhuma datagrama UDP pendente, continue
        except Exception as e:
            print(f"[AuthServer] Erro no servidor UDP: {e}")
            break # Erro fatal no loop do servidor UDP

    # Fechar sockets ao sair do loop
    udp_server_socket.close()
    tcp_server_socket.close()
    print("[AuthServer] Servidor de autenticação encerrado.")
