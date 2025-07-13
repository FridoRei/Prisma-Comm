import socket
import threading
from src.core.chat.globals import clientes_lock, handlers, authenticated_ips, authenticated_ips_lock # Importar a lista e o lock
from src.core.chat.client_handler import ClientHandler 

def broadcast_from_host(message: str, chat_widget_instance): 
    if not message:
        return
    
    message_with_prefix = f"[Host] {message}"

    with clientes_lock:
        current_handlers = handlers.copy()

    for handler in current_handlers:
        try:
            if handler._running:
                handler.send_to_client(message_with_prefix)
            else:
                print(f"[ChatServer] Handler para {handler.username} ({handler.addr}) não está rodando, pulando.")
        except Exception as e:
            print(f"[ChatServer] ERRO CRÍTICO no broadcast para {handler.username} ({handler.addr}): {e}")

def start_server(chat_widget_instance, port): 
    print("[ChatServer] Iniciando servidor de chat...")

    with clientes_lock:
        handlers.clear()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    host = '0.0.0.0'

    try:
        server_socket.bind((host, port))
        server_socket.listen(5)
        server_socket.settimeout(1.0) 
        print(f"[ChatServer] Servidor de chat escutando em {host}:{port}")

        if chat_widget_instance:
            chat_widget_instance.add_message_to_chat(f"Servidor de chat iniciado em {host}:{port}")

        global chat_server_running
        chat_server_running = True

        while chat_server_running: 
            try:
                conn, addr = server_socket.accept()
                client_ip = addr[0]
                print(f"[ChatServer] Tentativa de conexão de {addr}")

                with authenticated_ips_lock:
                    if client_ip in authenticated_ips:
                        print(f"[ChatServer] Conexão de {client_ip} aceita.")
                        
                        handler = ClientHandler(conn, addr)

                        thread = threading.Thread(target=handler.run, daemon=True)

                        if chat_widget_instance:
                            handler.new_message_for_host.connect(chat_widget_instance.add_message_to_chat)
                            handler.client_status_for_host.connect(chat_widget_instance.add_message_to_chat)

                        thread.start()
                    else:
                        print(f"[ChatServer] Conexão de {client_ip} rejeitada.")
                        conn.sendall("AUTH_REQUIRED\n".encode()) 
                        conn.close()

            except socket.timeout:
                pass
            except Exception as e:
                print(f"[ChatServer] Erro ao aceitar conexão: {e}")

    except Exception as e:
        print(f"[ChatServer] Erro fatal no servidor: {e}")
        if chat_widget_instance:
            chat_widget_instance.add_message_to_chat(f"Erro no servidor: {e}")
    finally:
        server_socket.close()
        print("[ChatServer] Servidor de chat encerrado.")

def stop_chat_server():
    global chat_server_running
    chat_server_running = False
    print("[ChatServer] Sinal para encerrar servidor de chat enviado.")
