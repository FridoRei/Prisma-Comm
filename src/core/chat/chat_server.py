import socket
import threading
from src.core.chat.globals import clientes_lock, handlers, connected_users_lock, connected_users, authenticated_ips, authenticated_ips_lock, client_aes_keys, client_aes_keys_lock
from src.core.chat.client_handler import ClientHandler
from cryptography.hazmat.primitives.asymmetric import ed25519
from src.core.network.dos_detector import DoSDetector
import datetime 
from src.core.crypto.aes_manager import AESManager
import os
import hashlib
import json

chat_server_running = False
FILE_MAX_SIZE = 10 * 1024 * 1024 

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

def handle_file_transfer(conn: socket.socket, addr: tuple, aes_manager: AESManager, dos_detector: DoSDetector, sender_username: str, total_data_length: int):
    client_ip = addr[0]
    print(f"[INFO] [ChatServer] Iniciando recebimento de arquivo de {addr} ({sender_username}).")

    if not dos_detector.anti_spam_message(client_ip):
        print(f"[SPAM] Transferência de arquivo de {client_ip} bloqueada por anti-spam.")
        return

    try:

        if total_data_length > FILE_MAX_SIZE + 4096:
            print(f"[WARNING] [ChatServer] Arquivo de {addr} excede o limite de tamanho ({total_data_length} bytes). Descartando.")
            bytes_to_consume = total_data_length
            while bytes_to_consume > 0:
                chunk = conn.recv(min(bytes_to_consume, 4096))
                if not chunk:
                    print(f"[WARNING] [ChatServer] Cliente {addr} desconectou durante o descarte do arquivo grande.")
                    return
                bytes_to_consume -= len(chunk)
            return

        encrypted_full_data = b''
        bytes_received = 0
        while bytes_received < total_data_length:
            chunk = conn.recv(min(total_data_length - bytes_received, 4096))
            if not chunk:
                print(f"[WARNING] [ChatServer] Cliente {addr} desconectou durante o recebimento do conteúdo do arquivo.")
                return
            encrypted_full_data += chunk
            bytes_received += len(chunk)

        parts = encrypted_full_data.split(b'|', 2)
        if len(parts) != 3:
            raise ValueError("Formato de dados de arquivo criptografado inválido do cliente.")

        nonce = parts[0]
        ciphertext = parts[1]
        tag = parts[2]

        decrypted_data_json = aes_manager.decrypt(nonce, ciphertext, tag)
        file_data = json.loads(decrypted_data_json)

        original_filename = file_data.get("filename")
        mime_type = file_data.get("mime_type")
        file_content_b64 = file_data.get("content")
        received_hash = file_data.get("hash")
        
        if not all([original_filename, mime_type, file_content_b64, received_hash]):
            raise ValueError("Dados de arquivo incompletos ou corrompidos.")

        file_content_bytes = AESManager.base64_to_bytes(file_content_b64)

        calculated_hash = hashlib.sha256(file_content_bytes).hexdigest()
        if calculated_hash != received_hash:
            print(f"[ERROR] [ChatServer] Erro de integridade no arquivo '{original_filename}' de {addr}. Hash inválido.")
            return 

        print(f"[INFO] [ChatServer] Arquivo '{original_filename}' ({mime_type}) de {addr} ({sender_username}) recebido e verificado. Retransmitindo...")

        file_data["sender_username"] = sender_username
        retransmit_data_json = json.dumps(file_data)

        broadcast_file_to_clients(retransmit_data_json.encode('utf-8'), conn) 

    except Exception as e:
        print(f"[ERROR] [ChatServer] Erro ao lidar com transferência de arquivo de {addr}: {e}")
        import traceback
        traceback.print_exc()

def broadcast_file_to_clients(file_json_bytes: bytes, sender_conn: socket.socket):
    """
    Retransmite um arquivo para todos os clientes conectados, exceto o remetente.
    Os dados do arquivo já devem estar em formato JSON (não criptografados).
    """
    with clientes_lock:
        current_handlers = handlers.copy()

    if not current_handlers:
        print("[INFO] [ChatServer] Nenhum cliente conectado para retransmissão de arquivo.")
        return

    for handler in current_handlers:
        if handler.client_socket != sender_conn and handler._running:
            try:
                with client_aes_keys_lock:
                    dest_aes_key = client_aes_keys.get(handler.addr[0])

                if dest_aes_key:
                    dest_aes_manager = AESManager(dest_aes_key)
                    
                    nonce, ciphertext, tag = dest_aes_manager.encrypt(file_json_bytes.decode('utf-8')) 
                    encrypted_file_data_for_client = nonce + b'|' + ciphertext + b'|' + tag
                    
                    handler.client_socket.sendall(len(encrypted_file_data_for_client).to_bytes(4, 'big'))
                    handler.client_socket.sendall(encrypted_file_data_for_client)
                    print(f"[INFO] [ChatServer] Arquivo retransmitido para {handler.username} ({handler.addr[0]}).")
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
                        handler.file_received_from_client.connect(
                            lambda filename, mime_type, file_content_bytes, sender_username, conn_obj, aes_mgr, dos_det:
                            threading.Thread(target=handle_file_transfer, args=(conn_obj, addr, aes_mgr, dos_det, sender_username, total_data_length), daemon=True).start()
                        )


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

