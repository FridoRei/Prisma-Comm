import socket
import threading
import time
from src.core.auth.token_manager import validar_token
from src.core.chat.globals import authenticated_ips, authenticated_ips_lock
from src.core.auth.rsa_manager import RSAManager

# REMOVA a linha: rsa_manager_instance = RSAManager()
# Ela não será mais uma instância global única para todas as requisições.

# Função para lidar com requisições de chave pública (TCP)
# Agora, handle_public_key_request recebe sua própria instância de RSAManager
def handle_public_key_request(conn, addr, rsa_manager_for_this_session):
    try:
        print(f"[AuthServer] Requisição de chave pública de {addr}")
        
        # Gerar um novo par de chaves efêmeras para ESTA sessão de autenticação
        rsa_manager_for_this_session.generate_ephemeral_keys()
        
        public_key_bytes = rsa_manager_for_this_session.get_public_key_bytes() 
        
        if public_key_bytes:
            conn.sendall(public_key_bytes)
            print(f"[AuthServer] Chave pública efêmera enviada para {addr}")
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
    tcp_server_socket.listen(5) # Pode aumentar o listen backlog
    tcp_server_socket.settimeout(1.0)

    print(f"[AuthServer] Servidor de autenticação (UDP) e chave pública (TCP) iniciado na porta {auth_port}")

    # Dicionário para armazenar as instâncias de RSAManager por IP do cliente
    # Isso é necessário porque a requisição UDP (token) virá depois da TCP (chave pública)
    # e precisamos da chave privada correta para descriptografar.
    # Usaremos o IP do cliente como chave.
    session_rsa_managers = {}
    session_rsa_managers_lock = threading.Lock() # Para acesso seguro ao dicionário

    while not stop_event.is_set():
        # Lidar com conexões TCP (chave pública)
        try:
            tcp_conn, tcp_addr = tcp_server_socket.accept()
            client_ip = tcp_addr[0]
            
            # Cria uma NOVA instância de RSAManager para ESTE cliente/sessão
            new_rsa_manager = RSAManager()
            
            # Armazena esta instância no dicionário para uso posterior na requisição UDP
            with session_rsa_managers_lock:
                session_rsa_managers[client_ip] = new_rsa_manager
            
            # Inicia uma nova thread para lidar com a requisição TCP, passando a instância
            threading.Thread(target=handle_public_key_request, 
                             args=(tcp_conn, tcp_addr, new_rsa_manager), # Passa a instância específica
                             daemon=True).start()
        except socket.timeout:
            pass

        # Lidar com datagramas UDP (autenticação de token)
        try:
            encrypted_token, addr = udp_server_socket.recvfrom(256)
            client_ip = addr[0] # Obtém o IP do cliente que enviou o datagrama
            print(f"[AuthServer] Recebido datagrama UDP de {addr}")

            # Tenta obter a instância de RSAManager associada a este IP
            current_rsa_manager = None
            with session_rsa_managers_lock:
                current_rsa_manager = session_rsa_managers.get(client_ip)

            if current_rsa_manager:
                try:
                    # Descriptografar o token usando a chave privada efêmera CORRETA
                    token = current_rsa_manager.decrypt_token(encrypted_token)
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
                    # Limpar as chaves efêmeras e remover do dicionário após a tentativa de autenticação
                    current_rsa_manager.clear_keys()
                    with session_rsa_managers_lock:
                        if client_ip in session_rsa_managers:
                            del session_rsa_managers[client_ip]
                    print(f"[AuthServer] Chaves efêmeras e sessão para {client_ip} limpas.")
            else:
                # Caso o cliente UDP envie um token sem ter solicitado a chave pública antes
                print(f"[AuthServer] Token UDP recebido de {client_ip} sem chave efêmera correspondente. Rejeitando.")
                udp_server_socket.sendto(b"AUTH_FAILURE", addr)

        except socket.timeout:
            pass
        except Exception as e:
            print(f"[AuthServer] Erro no servidor UDP: {e}")
            break

    # Fechar sockets ao sair do loop
    udp_server_socket.close()
    tcp_server_socket.close()
    print("[AuthServer] Servidor de autenticação encerrado.")
