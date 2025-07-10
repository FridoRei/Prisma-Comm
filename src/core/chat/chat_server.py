import socket
import threading
from src.core.chat.globals import clientes_lock, handlers 
from src.core.chat.client_handler import ClientHandler 

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
                print(f"[Servidor] Enviando mensagem do host para {handler.username} ({handler.addr})...")
                handler.send_to_client(message_with_prefix)
                print(f"[Servidor] Mensagem enviada com sucesso para {handler.username} ({handler.addr}).")
            else:
                print(f"[Servidor] Handler para {handler.username} ({handler.addr}) não está rodando, pulando.")
        except Exception as e:
            print(f"[Servidor] ERRO CRÍTICO no broadcast para {handler.username} ({handler.addr}): {e}")

def start_server(chat_widget_instance, port): 
    print("[Servidor] Iniciando servidor de chat...")

    with clientes_lock:
        handlers.clear()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    host = '0.0.0.0'

    try:
        server_socket.bind((host, port))
        server_socket.listen(5)
        print(f"[Servidor] Servidor de chat escutando em {host}:{port}")

        if chat_widget_instance:
            chat_widget_instance.add_message_to_chat(f"Servidor de chat iniciado em {host}:{port}")

        while True:
            try:
                conn, addr = server_socket.accept()
                print(f"[Servidor] Nova conexão de {addr}")

                handler = ClientHandler(conn, addr)

                thread = threading.Thread(target=handler.run, daemon=True)

                if chat_widget_instance:
                    handler.new_message_for_host.connect(chat_widget_instance.add_message_to_chat)
                    handler.client_status_for_host.connect(chat_widget_instance.add_message_to_chat)

                thread.start()

            except Exception as e:
                print(f"[Servidor] Erro ao aceitar conexão: {e}")

    except Exception as e:
        print(f"[Servidor] Erro fatal no servidor: {e}")
        if chat_widget_instance:
            chat_widget_instance.add_message_to_chat(f"Erro no servidor: {e}")
    finally:
        server_socket.close()
        print("[Servidor] Servidor de chat encerrado.")

