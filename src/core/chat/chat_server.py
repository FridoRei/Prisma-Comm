import socket
import threading
import ssl # Adicionar import
from src.core.chat.globals import clientes_lock, handlers, authenticated_ips, authenticated_ips_lock
from src.core.chat.client_handler import ClientHandler
from src.config.settings import SERVER_CERT, SERVER_KEY # Adicionar import

def broadcast_from_host(message: str, chat_widget_instance):
    if not message:
        return

    if chat_widget_instance:
        chat_widget_instance.add_message_to_chat(f"Você (Host): {message}")

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

    # Configuração SSL para o servidor de chat
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=SERVER_CERT, keyfile=SERVER_KEY)
    context.verify_mode = ssl.CERT_NONE # Não verificar certificado do cliente para o chat, apenas autenticação de token

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    host = '0.0.0.0'

    try:
        server_socket.bind((host, port))
        server_socket.listen(5)
        server_socket.settimeout(1.0)

        # Envolver o socket do servidor com TLS
        ssl_server_socket = context.wrap_socket(server_socket, server_side=True)

        print(f"[ChatServer] Servidor de chat escutando em {host}:{port} (TLS/SSL)")

        if chat_widget_instance:
            chat_widget_instance.add_message_to_chat(f"Servidor de chat iniciado em {host}:{port} (TLS/SSL)")

        global chat_server_running
        chat_server_running = True

        while chat_server_running:
            try:
                conn, addr = ssl_server_socket.accept() # Aceitar conexão TLS
                client_ip = addr[0]
                print(f"[ChatServer] Tentativa de conexão de {addr}")

                with authenticated_ips_lock:
                    if client_ip in authenticated_ips:
                        print(f"[ChatServer] IP {client_ip} autenticado. Aceitando conexão.")

                        handler = ClientHandler(conn, addr)

                        thread = threading.Thread(target=handler.run, daemon=True)

                        if chat_widget_instance:
                            handler.new_message_for_host.connect(chat_widget_instance.add_message_to_chat)
                            handler.client_status_for_host.connect(chat_widget_instance.add_message_to_chat)

                        thread.start()
                    else:
                        print(f"[ChatServer] IP {client_ip} NÃO autenticado. Negando conexão.")
                        conn.sendall("AUTH_REQUIRED\n".encode())
                        conn.close()

            except socket.timeout:
                pass
            except ssl.SSLError as e: # Capturar erros SSL durante a aceitação
                print(f"[ChatServer] Erro SSL ao aceitar conexão: {e}")
                if 'conn' in locals():
                    conn.close()
            except Exception as e:
                print(f"[ChatServer] Erro ao aceitar conexão: {e}")

    except Exception as e:
        print(f"[ChatServer] Erro fatal no servidor: {e}")
        if chat_widget_instance:
            chat_widget_instance.add_message_to_chat(f"Erro no servidor: {e}")
    finally:
        if 'ssl_server_socket' in locals() and ssl_server_socket:
            ssl_server_socket.close()
        server_socket.close()
        print("[ChatServer] Servidor de chat encerrado.")

def stop_chat_server():
    global chat_server_running
    chat_server_running = False
    print("[ChatServer] Sinal para encerrar servidor de chat enviado.")
