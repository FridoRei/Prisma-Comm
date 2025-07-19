import socket
import threading
import traceback
from queue import Empty
from src.core.chat.globals import clientes_lock, handlers, connected_users_lock, connected_users, authenticated_ips, authenticated_ips_lock, client_aes_keys, client_aes_keys_lock, file_transfer_queue
from src.core.chat.client_handler import ClientHandler
from cryptography.hazmat.primitives.asymmetric import ed25519
from src.core.network.dos_detector import DoSDetector
import datetime
import time
from src.core.crypto.aes_manager import AESManager
import os
import hashlib
import json

chat_server_running = False
FILE_MAX_SIZE = 10 * 1024 * 1024

def file_queue_processor(dos_detector: DoSDetector, chat_widget_instance):
    print("[INFO] [ChatServer] Thread de processamento de fila de arquivos iniciada.")
    while chat_server_running: 
        try:
            file_data, sender_conn, aes_manager = file_transfer_queue.get(timeout=1) 
            handle_file_transfer(file_data, sender_conn, aes_manager, dos_detector, chat_widget_instance)
            file_transfer_queue.task_done() 
        except Empty: 
            continue    
        except Exception as e:
            print(f"[ERROR] [ChatServer] Erro na thread de processamento de fila de arquivos: {e}")
            traceback.print_exc()
        time.sleep(0.1) 
    print("[INFO] [ChatServer] Thread de processamento de fila de arquivos encerrada.")

def broadcast_from_host(message: str, chat_widget_instance):
    if not message:
        print("[WARNING] [ChatServer] Tentativa de broadcast de mensagem vazia.")
        return

    message_data = {
        "type": "text_message",
        "content": message,
        "hash": hashlib.sha256(message.encode('utf-8')).hexdigest(),
        "sender_username": "Host"
    }

    with clientes_lock:
        current_handlers = handlers.copy()

    if not current_handlers:
        print("[INFO] [ChatServer] Nenhum cliente conectado para broadcast.")
        return

    for handler in current_handlers:
        try:
            if handler._running:
                handler.send_to_client(message_data) 
            else:
                print(f"[WARNING] [ChatServer] Handler para {handler.username} ({handler.addr}) não está rodando, pulando broadcast.")
        except Exception as e:
            print(f"[ERROR] [ChatServer] Erro ao tentar broadcast para {handler.username} ({handler.addr}): {e}")

def handle_file_transfer(file_data_dict: dict, sender_conn: socket.socket, aes_manager: AESManager, dos_detector: DoSDetector, chat_widget_instance):
    client_ip = sender_conn.getpeername()[0] 
    sender_username = file_data_dict.get("sender_username", "Desconhecido")
    original_filename = file_data_dict.get("filename", "arquivo_desconhecido")
    mime_type = file_data_dict.get("mime_type", "application/octet-stream")
    received_hash = file_data_dict.get("hash")
    file_content_b64 = file_data_dict.get("content")

    if not dos_detector.anti_spam_message(client_ip):
        print(f"[SPAM] Transferência de arquivo de {client_ip} bloqueada por anti-spam.")
        return

    try:
        estimated_file_size = len(AESManager.base64_to_bytes(file_content_b64))
        if estimated_file_size > FILE_MAX_SIZE:
            print(f"[WARNING] [ChatServer] Arquivo de {client_ip} excede o limite de tamanho ({estimated_file_size} bytes). Descartando.")
            return

        calculated_hash = hashlib.sha256(AESManager.base64_to_bytes(file_content_b64)).hexdigest()
        if calculated_hash != received_hash:
            print(f"[ERROR] [ChatServer] Erro de integridade no arquivo '{original_filename}' de {client_ip}. Hash inválido.")
            return

        file_content_bytes = AESManager.base64_to_bytes(file_content_b64)
        if chat_widget_instance:
            chat_widget_instance.add_file_to_chat(
                original_filename,
                mime_type,
                file_content_bytes, 
                sender_username
            )
            chat_widget_instance.add_message_to_chat(f"[INFO] Arquivo '{original_filename}' de {sender_username} recebido pelo Host.")        
            
        broadcast_file_to_clients(file_data_dict, sender_conn) 

    except Exception as e:
        print(f"[ERROR] [ChatServer] Erro ao lidar com transferência de arquivo de {client_ip}: {e}")
        traceback.print_exc()

def broadcast_file_to_clients(file_data_dict: dict, sender_conn: socket.socket):
    """
    Retransmite um arquivo para todos os clientes conectados, exceto o remetente.
    Os dados do arquivo já devem estar em formato JSON (não criptografados).
    """
    with clientes_lock:
        current_handlers = handlers.copy()

    if not current_handlers:
        print("[INFO] [ChatServer] Nenhum cliente conectado para retransmissão de arquivo.")
        return

    # Converter o dicionário para JSON
    json_file_str = json.dumps(file_data_dict)
    
    for handler in current_handlers:
        if handler.client_socket != sender_conn and handler._running:
            try:
                with client_aes_keys_lock:
                    dest_aes_key = client_aes_keys.get(handler.addr[0])

                if dest_aes_key:
                    dest_aes_manager = AESManager(dest_aes_key)
                    
                    # Criptografar os dados JSON
                    nonce, ciphertext, tag = dest_aes_manager.encrypt(json_file_str) 

                    encrypted_file_data_for_client = nonce + b'<-->' + ciphertext + b'<-->' + tag

                    # Enviar tamanho primeiro
                    handler.client_socket.sendall(len(encrypted_file_data_for_client).to_bytes(4, 'big'))
                    # Enviar dados criptografados
                    handler.client_socket.sendall(encrypted_file_data_for_client)
                else:
                    print(f"[WARNING] [ChatServer] ERRO: Chave AES não encontrada para {handler.username} ({handler.addr[0]}). Não foi possível retransmitir arquivo.")
            except BrokenPipeError:
                print(f"[ERROR] [ChatServer] Conexão quebrada ao tentar retransmitir arquivo para {handler.username} ({handler.addr[0]}).")
                handler.stop()
            except Exception as e:
                print(f"[ERROR] [ChatServer] Erro na retransmissão criptografada de arquivo para {handler.username} ({handler.addr[0]}): {e}")



def start_server(chat_widget_instance, port, dos_detector: DoSDetector, host_client_data_receive_timeout: int = 5):
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

        file_processor_thread = threading.Thread(target=file_queue_processor, args=(dos_detector, chat_widget_instance), daemon=True)
        file_processor_thread.start()
        print("[INFO] [ChatServer] Thread de processamento de fila de arquivos iniciada.")

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

                is_ip_authenticated = False
                session_key_for_client = None
                with authenticated_ips_lock:
                    if client_ip in authenticated_ips:
                        is_ip_authenticated = True
                        del authenticated_ips[client_ip]

                with client_aes_keys_lock:
                    if client_ip in client_aes_keys:
                        session_key_for_client = client_aes_keys[client_ip]

                if is_ip_authenticated and session_key_for_client:
                    try:
                        temp_aes_manager_for_first_message = AESManager(session_key_for_client)
                        nonce, ciphertext, tag = temp_aes_manager_for_first_message.encrypt("ACCEPTED")
                        encrypted_accepted_b64 = f"{AESManager.bytes_to_base64(nonce)}|{AESManager.bytes_to_base64(ciphertext)}|{AESManager.bytes_to_base64(tag)}"
                        conn.sendall(encrypted_accepted_b64.encode('utf-8'))
                        print(f"[INFO] [ChatServer] Conexão ao chat de {client_ip} aceita.")
                    except Exception as e:
                        print(f"[ERROR] [ChatServer] Erro ao criptografar/enviar 'ACCEPTED' para {client_ip}: {e}")
                        conn.sendall(b"ERROR_ENCRYPTING_ACCEPTED\n")
                        conn.close()
                        continue

                    handler = ClientHandler(conn, addr, session_key_for_client, dos_detector, host_client_data_receive_timeout)

                    thread = threading.Thread(target=handler.run, daemon=True)

                    if chat_widget_instance:
                        handler.new_message_for_host.connect(chat_widget_instance.add_message_to_chat)
                        handler.client_status_for_host.connect(chat_widget_instance.add_message_to_chat)
                        handler.user_list_updated.connect(chat_widget_instance.update_user_list)
                        
                    thread.start()
                else:
                    print(f"[WARNING] [ChatServer] Conexão ao chat de {client_ip} rejeitada por falta de autenticação ou chave AES \n.")
                    conn.sendall(b"AUTH_REQUIRED\n")
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
            chat_widget_instance.add_message_to_chat(f"[CRITICAL] Erro ao iniciar servidor: A porta pode estar em uso ou permissão negada.")
    except Exception as e:
        print(f"[CRITICAL] [ChatServer] Erro fatal inesperado no servidor de chat: {e}")
        if chat_widget_instance:
            chat_widget_instance.add_message_to_chat(f"[CRITICAL] Erro fatal no servidor. Por favor, reinicie o aplicativo.")
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

