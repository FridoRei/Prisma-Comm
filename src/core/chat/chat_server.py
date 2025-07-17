import socket
import threading
from src.core.chat.globals import clientes_lock, handlers, connected_users_lock, connected_users, authenticated_sessions, authenticated_sessions_lock, ip_to_token_map_lock, ip_to_token_map
from src.core.chat.client_handler import ClientHandler
from cryptography.hazmat.primitives.asymmetric import ed25519
from src.core.network.dos_detector import DoSDetector
import datetime 

chat_server_running = False

def broadcast_from_host(message: str, chat_widget_instance):
    if not message:
        print("[WARNING] [ChatServer] Tentativa de broadcast de mensagem vazia.")
        return

    message_with_prefix = f"[Host] {message}"

    with clientes_lock:
        current_handlers = handlers.copy()

    if not current_handlers:
        print("[INFO] [ChatServer] Nenhum cliente conectado para broadcast.")
        return

    for handler in current_handlers:
        try:
            if handler._running:
                handler.send_to_client(message_with_prefix)
            else:
                print(f"[WARNING] [ChatServer] Handler para {handler.username} ({handler.addr}) não está rodando, pulando broadcast.")
        except Exception as e:
            print(f"[ERROR] [ChatServer] Erro ao tentar broadcast para {handler.username} ({handler.addr}): {e}")

def start_server(chat_widget_instance, port, host_ed25519_private_key: ed25519.Ed25519PrivateKey, dos_detector: DoSDetector, host_client_data_receive_timeout: int = 5):
    print("[INFO] [ChatServer] Iniciando servidor de chat...")

    with clientes_lock:
        handlers.clear()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    host = '0.0.0.0'

    try:
        server_socket.bind((host, port))
        server_socket.listen(5)
        server_socket.settimeout(3.0)

        if chat_widget_instance:
            chat_widget_instance.add_message_to_chat(f"[INFO] Servidor de chat iniciado em {host}:{port}")

        global chat_server_running
        chat_server_running = True

        while chat_server_running:
            try:
                conn, addr = server_socket.accept()
                client_ip = addr[0]
                print(f"[INFO] [ChatServer] Tentativa de conexão ao chat de {addr}")

                if not dos_detector.check_and_record(client_ip):
                    print(f"[WARNING] [ChatServer] Conexão de chat de {addr} bloqueada por DoSDetector.")
                    conn.sendall(b"REFUSED\n")
                    conn.close()
                    continue

                with connected_users_lock:
                    if client_ip in connected_users:
                        print(f"[WARNING] [ChatServer] Cliente {client_ip} já está conectado. Recusando nova conexão.")
                        conn.sendall(b"REFUSED\n") 
                        conn.close()
                        continue

                token_data = conn.recv(1024).decode('utf-8').strip()
                if not token_data.startswith("SESSION_TOKEN:"):
                    print(f"[WARNING] [ChatServer] Conexão de {client_ip} rejeitada: Token de sessão ausente ou formato inválido.")
                    conn.sendall(b"AUTH_REQUIRED\n") 
                    conn.close()
                    continue

                session_token = token_data.split(":", 1)[1]

                is_token_valid = False
                with authenticated_sessions_lock:
                    token_info = authenticated_sessions.get(session_token)
                    if token_info:
                        if token_info["ip"] == client_ip:
                            if datetime.datetime.now() - token_info["timestamp"] < datetime.timedelta(seconds=300):
                                is_token_valid = True
                            else:
                                print(f"[WARNING] [ChatServer] Token de sessão de {client_ip} expirado.")
                        else:
                            print(f"[WARNING] [ChatServer] Token de sessão de {client_ip} inválido: IP não corresponde.")
                    else:
                        print(f"[WARNING] [ChatServer] Token de sessão de {client_ip} não encontrado na lista de sessões ativas.")

                if is_token_valid:
                    with authenticated_sessions_lock:
                        if session_token in authenticated_sessions:
                            del authenticated_sessions[session_token]
                    with ip_to_token_map_lock:
                        if client_ip in ip_to_token_map and ip_to_token_map[client_ip] == session_token:
                            del ip_to_token_map[client_ip]

                    conn.sendall(b"TOKEN_ACCEPTED\n")
                    print(f"[INFO] [ChatServer] Conexão ao chat de {client_ip} aceita (token válido).")

                    handler = ClientHandler(conn, addr, host_ed25519_private_key, dos_detector, host_client_data_receive_timeout)

                    thread = threading.Thread(target=handler.run, daemon=True)

                    if chat_widget_instance:
                        handler.new_message_for_host.connect(chat_widget_instance.add_message_to_chat)
                        handler.client_status_for_host.connect(chat_widget_instance.add_message_to_chat)
                        handler.user_list_updated.connect(chat_widget_instance.update_user_list)

                    thread.start()
                else:
                    print(f"[WARNING] [ChatServer] Conexão ao chat de {client_ip} rejeitada. Token de sessão inválido ou expirado.")
                    conn.sendall(b"INVALID_SESSION_TOKEN\n")
                    conn.close()

            except socket.timeout:
                pass
            except OSError as e:
                if chat_server_running:
                    print(f"[ERROR] [ChatServer] Erro de sistema operacional ao aceitar conexão: {e}")
                else:
                    print(f"[INFO] [ChatServer] Socket fechado durante accept() enquanto o servidor estava parando.")
            except Exception as e:
                print(f"[CRITICAL] [ChatServer] Erro inesperado ao aceitar conexão: {e}")

    except OSError as e:
        print(f"[CRITICAL] [ChatServer] Erro de sistema operacional ao iniciar servidor (bind/listen): {e}. Porta {port} pode estar em uso ou permissão negada.")
        if chat_widget_instance:
            chat_widget_instance.add_message_to_chat(f"[CRITICAL] Erro ao iniciar servidor: {e}. Porta em uso?")
    except Exception as e:
        print(f"[CRITICAL] [ChatServer] Erro fatal inesperado no servidor de chat: {e}")
        if chat_widget_instance:
            chat_widget_instance.add_message_to_chat(f"[CRITICAL] Erro fatal no servidor: {e}")
    finally:
        server_socket.close()
        print("[INFO] [ChatServer] Servidor de chat encerrado.")

def stop_chat_server():
    global chat_server_running
    if chat_server_running:
        chat_server_running = False
        print("[INFO] [ChatServer] Sinal para encerrar servidor de chat enviado.")
    else:
        print("[INFO] [ChatServer] Servidor de chat já está parado ou não foi iniciado.")

