# src/core/chat/chat_server.py
import socket
import threading
# Importar a lista de autorizados e seu lock
from src.core.chat.globals import clientes_lock, handlers, clientes_autorizados, autorizados_lock
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
        handlers.clear() # Limpa handlers antigos se houver

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    host = '0.0.0.0' # Escuta em todas as interfaces disponíveis

    try:
        server_socket.bind((host, port))
        server_socket.listen(5) # Permite até 5 conexões pendentes
        server_socket.settimeout(1.0) # Define um timeout para accept para permitir encerramento limpo

        print(f"[Servidor] Servidor de chat escutando em {host}:{port}")

        if chat_widget_instance:
            chat_widget_instance.add_message_to_chat(f"Servidor de chat iniciado em {host}:{port}")

        while True:
            try:
                conn, addr = server_socket.accept()
                client_ip = addr[0] # Obter o IP do cliente

                # --- VERIFICAÇÃO DE AUTORIZAÇÃO ---
                with autorizados_lock:
                    if client_ip not in clientes_autorizados:
                        print(f"[Servidor] Conexão recusada de {addr}: Cliente não autorizado. Lista de autorizados: {clientes_autorizados}")
                        try:
                            # Envia uma mensagem para o cliente informando que a autenticação é necessária
                            conn.sendall(b"AUTH_REQUIRED_CHAT")
                        except Exception as send_e:
                            print(f"[Servidor] Erro ao enviar AUTH_REQUIRED_CHAT para {addr}: {send_e}")
                        conn.close()
                        continue # Pula para a próxima iteração do loop, não processa esta conexão

                print(f"[Servidor] Nova conexão autorizada de {addr}. Lista de autorizados: {clientes_autorizados}")

                # Se o cliente está autorizado, cria um handler para ele
                handler = ClientHandler(conn, addr)

                # Cria uma nova thread para lidar com o cliente
                thread = threading.Thread(target=handler.run, daemon=True)

                # Conecta os sinais do handler ao chat_widget da GUI
                if chat_widget_instance:
                    handler.new_message_for_host.connect(chat_widget_instance.add_message_to_chat)
                    handler.client_status_for_host.connect(chat_widget_instance.add_message_to_chat)

                thread.start()

            except socket.timeout:
                # Isso é normal, significa que não houve conexões no último segundo
                pass
            except Exception as e:
                if threading.main_thread().is_alive(): # Verifica se a thread principal ainda está ativa
                    print(f"[Servidor] Erro ao aceitar conexão: {e}")
                else:
                    # Se a thread principal não está ativa, provavelmente a aplicação está fechando
                    print("[Servidor] Servidor de chat encerrando devido ao fechamento da aplicação.")
                    break # Sai do loop while True

    except Exception as e:
        print(f"[Servidor] Erro fatal no servidor: {e}")
        if chat_widget_instance:
            chat_widget_instance.add_message_to_chat(f"Erro no servidor: {e}")
    finally:
        server_socket.close()
        print("[Servidor] Servidor de chat encerrado.")
