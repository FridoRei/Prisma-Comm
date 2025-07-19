import socket
import threading
import time
import datetime
import uuid
import hashlib
from src.core.auth.token_manager import verificar_senha
from src.core.chat.globals import authenticated_ips, authenticated_ips_lock, client_aes_keys, client_aes_keys_lock
from src.core.network.dos_detector import DoSDetector
from src.core.network.request_limiter import RequestLimiter
from src.core.crypto.ecc_manager import ECCManager
from src.core.crypto.aes_manager import AESManager
from cryptography.hazmat.primitives.asymmetric import ed25519

REQUEST_MAX_LENGTH = 600
AUTH_HANDSHAKE_TIMEOUT = 5 

def is_utf8_valid(data: bytes) -> bool:
    try:
        data.decode('utf-8')
        return True
    except UnicodeDecodeError:
        return False

def handle_auth_client(conn: socket.socket, addr: tuple, host_password: str, dos_detector: DoSDetector, request_limiter: RequestLimiter, host_ed25519_private_key: ed25519.Ed25519PrivateKey):
    client_ip = addr[0]
    print(f"[INFO] [AuthServer] Nova conexão de autenticação de {addr}.")

    if not dos_detector.check_and_record(client_ip):
        print(f"[WARNING] [AuthServer] Conexão de autenticação de {addr} bloqueada por DoSDetector.")
        conn.sendall(b"REFUSED\n")
        conn.close()
        return

    with authenticated_ips_lock:
        if client_ip in authenticated_ips:
            print(f"[INFO] [AuthServer] Cliente {client_ip} já autenticado. Sinalizando para o cliente.")
            conn.sendall(b"ALREADY_AUTHENTICATED\n")
            conn.close()
            return

    ecc_manager = ECCManager()
    ecc_manager._ed25519_private_key = host_ed25519_private_key
    ecc_manager._ed25519_public_key = host_ed25519_private_key.public_key()

    temp_aes_manager = None
    
    try:
        conn.settimeout(AUTH_HANDSHAKE_TIMEOUT)

        ecc_manager.generate_x25519_keys()
        server_x25519_public_bytes = ecc_manager.get_x25519_public_key_bytes()
        signature = ecc_manager.sign_data(server_x25519_public_bytes)

        handshake_data = f"{ECCManager.bytes_to_base64(server_x25519_public_bytes)}|{AESManager.bytes_to_base64(signature)}"
        conn.sendall(handshake_data.encode('utf-8'))

        client_handshake_response_bytes = conn.recv(2048)
        if not client_handshake_response_bytes:
            raise ValueError("Dados de handshake do cliente vazios.")
        if not is_utf8_valid(client_handshake_response_bytes):
            raise ValueError("Dados de handshake do cliente não são UTF-8 válidos.")
        if request_limiter.is_request_too_large(client_handshake_response_bytes):
            raise ValueError("Handshake do cliente excedeu o limite de tamanho.")

        client_x25519_public_b64 = client_handshake_response_bytes.decode('utf-8').strip()
        client_x25519_public_bytes = ECCManager.base64_to_bytes(client_x25519_public_b64)

        derived_temp_aes_key = ecc_manager.derive_shared_key(client_x25519_public_bytes)
        temp_aes_manager = AESManager(derived_temp_aes_key)

        handshake_success_message = "ECC_HANDSHAKE_SUCCESS"
        nonce, ciphertext, tag = temp_aes_manager.encrypt(handshake_success_message)
        encrypted_handshake_success_b64 = f"{AESManager.bytes_to_base64(nonce)}|{AESManager.bytes_to_base64(ciphertext)}|{AESManager.bytes_to_base64(tag)}"
        conn.sendall(encrypted_handshake_success_b64.encode('utf-8'))
        print(f"[SUCCESS] [AuthServer] Handshake concluído com {addr}.")

        encrypted_password_hash_bytes = conn.recv(4096)
        if not encrypted_password_hash_bytes:
            raise ValueError("Hash da senha criptografado não recebido.")
        if not is_utf8_valid(encrypted_password_hash_bytes):
            raise ValueError("Hash da senha criptografado não é UTF-8 válido.")
        if request_limiter.is_request_too_large(encrypted_password_hash_bytes):
            raise ValueError("Hash da senha criptografado excedeu o limite de tamanho.")

        parts = encrypted_password_hash_bytes.decode('utf-8').split('|')
        if len(parts) != 3:
            raise ValueError("Formato de hash de senha criptografado inválido.")

        nonce = AESManager.base64_to_bytes(parts[0])
        ciphertext = AESManager.base64_to_bytes(parts[1])
        tag = AESManager.base64_to_bytes(parts[2])

        decrypted_client_password_hash = temp_aes_manager.decrypt(nonce, ciphertext, tag)

        if verificar_senha(host_password, decrypted_client_password_hash):

            session_aes_manager = AESManager() 
            session_aes_key_bytes = session_aes_manager.get_key()
            
            nonce_key, cipher_key, tag_key = temp_aes_manager.encrypt(AESManager.bytes_to_base64(session_aes_key_bytes))
            encrypted_session_key_b64 = f"{AESManager.bytes_to_base64(nonce_key)}|{AESManager.bytes_to_base64(cipher_key)}|{AESManager.bytes_to_base64(tag_key)}"
            conn.sendall(encrypted_session_key_b64.encode('utf-8'))

            confirmation_message = f"CONFIRM_SESSION_KEY_{uuid.uuid4()}"
            nonce_conf, cipher_conf, tag_conf = session_aes_manager.encrypt(confirmation_message)
            encrypted_confirmation_b64 = f"{AESManager.bytes_to_base64(nonce_conf)}|{AESManager.bytes_to_base64(cipher_conf)}|{AESManager.bytes_to_base64(tag_conf)}"
            conn.sendall(encrypted_confirmation_b64.encode('utf-8'))

            encrypted_client_confirmation_bytes = conn.recv(4096)
            if not encrypted_client_confirmation_bytes:
                raise ValueError("Confirmação do cliente não recebida.")
            if not is_utf8_valid(encrypted_client_confirmation_bytes):
                raise ValueError("Confirmação do cliente não é UTF-8 válida.")
            if request_limiter.is_request_too_large(encrypted_client_confirmation_bytes):
                raise ValueError("Confirmação do cliente excedeu o limite de tamanho.")

            parts_client_conf = encrypted_client_confirmation_bytes.decode('utf-8').split('|')
            if len(parts_client_conf) != 3:
                raise ValueError("Formato de confirmação do cliente inválido.")

            nonce_client_conf = AESManager.base64_to_bytes(parts_client_conf[0])
            cipher_client_conf = AESManager.base64_to_bytes(parts_client_conf[1])
            tag_client_conf = AESManager.base64_to_bytes(parts_client_conf[2])

            decrypted_client_confirmation = session_aes_manager.decrypt(nonce_client_conf, cipher_client_conf, tag_client_conf)
            
            if decrypted_client_confirmation == confirmation_message:
                
                with client_aes_keys_lock:
                    client_aes_keys[client_ip] = session_aes_key_bytes
                with authenticated_ips_lock:
                    authenticated_ips[client_ip] = datetime.datetime.now() 

                nonce_final, cipher_final, tag_final = session_aes_manager.encrypt("AUTH_SUCCESS")
                encrypted_final_success_b64 = f"{AESManager.bytes_to_base64(nonce_final)}|{AESManager.bytes_to_base64(cipher_final)}|{AESManager.bytes_to_base64(tag_final)}"
                conn.sendall(encrypted_final_success_b64.encode('utf-8'))
                print(f"[SUCCESS] [AuthServer] Autenticação completa para {addr}.")

            else:
                print(f"[WARNING] [AuthServer] Confirmação de chave de sessão FALHOU para {addr}. Conexão cortada.")
                nonce_fail, cipher_fail, tag_fail = session_aes_manager.encrypt("AUTH_FAILURE_KEY_CONFIRMATION")
                encrypted_fail_b64 = f"{AESManager.bytes_to_base64(nonce_fail)}|{AESManager.bytes_to_base64(cipher_fail)}|{AESManager.bytes_to_base64(tag_fail)}"
                conn.sendall(encrypted_fail_b64.encode('utf-8'))
                conn.close()
                return

        else:
            print(f"[WARNING] [AuthServer] Senha INCORRETA para {addr}. Autenticação falhou.")
            nonce_fail, cipher_fail, tag_fail = temp_aes_manager.encrypt("AUTH_FAILURE_PASSWORD")
            encrypted_fail_b64 = f"{AESManager.bytes_to_base64(nonce_fail)}|{AESManager.bytes_to_base64(cipher_fail)}|{AESManager.bytes_to_base64(tag_fail)}"
            conn.sendall(encrypted_fail_b64.encode('utf-8'))
            conn.close()
            return

    except socket.timeout:
        print(f"[ERROR] [AuthServer] Timeout durante a autenticação com {addr}.")
        try:
            conn.sendall(b"AUTH_FAILURE_TIMEOUT\n")
        except: pass
    except ValueError as e:
        print(f"[ERROR] [AuthServer] Erro de validação de dados com {addr}: {e}")
        try:
            conn.sendall(b"AUTH_FAILURE_DATA_ERROR\n")
        except: pass
    except Exception as e:
        print(f"[CRITICAL] [AuthServer] Erro inesperado durante a autenticação com {addr}: {e}")
        traceback.print_exc() 
        try:
            conn.sendall(b"AUTH_FAILURE_SERVER_ERROR\n")
        except: pass
    finally:
        ecc_manager.clear_x25519_keys() 
        if temp_aes_manager:
            del temp_aes_manager 
        try:
            conn.close()
        except Exception as e:
            print(f"[ERROR] [AuthServer] Erro ao fechar conexão com {addr}: {e}")


def run_auth_server(auth_port: int, stop_event: threading.Event, host_password: str, dos_detector: DoSDetector, host_ed25519_private_key: ed25519.Ed25519PrivateKey):
    tcp_server_socket = None
    request_limiter = RequestLimiter(max_length=REQUEST_MAX_LENGTH)

    try:
        tcp_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp_server_socket.bind(('0.0.0.0', auth_port))
        tcp_server_socket.listen(5)
        tcp_server_socket.settimeout(1.0) 
        print(f"[INFO] [AuthServer] Servidor de autenticação TCP iniciado na porta {auth_port}.")

        while not stop_event.is_set():
            try:
                conn, addr = tcp_server_socket.accept()
                threading.Thread(target=handle_auth_client, args=(conn, addr, host_password, dos_detector, request_limiter, host_ed25519_private_key), daemon=True).start()
            except socket.timeout:
                pass 
            except OSError as e:
                if stop_event.is_set():
                    print(f"[INFO] [AuthServer] Socket TCP fechado durante accept() enquanto o servidor estava parando.")
                else:
                    print(f"[ERROR] [AuthServer] Erro de sistema operacional ao aceitar conexão TCP: {e}")
            except Exception as e:
                print(f"[CRITICAL] [AuthServer] Erro inesperado ao aceitar conexão TCP: {e}")
                traceback.print_exc() 

    except OSError as e:
        print(f"[CRITICAL] [AuthServer] Erro ao iniciar servidor de autenticação: {e}. Porta {auth_port} pode estar em uso ou permissão negada.")
    except Exception as e:
        print(f"[CRITICAL] [AuthServer] Erro fatal inesperado no servidor de autenticação: {e}")
        traceback.print_exc() 
    finally:
        stop_event.set()
        if tcp_server_socket:
            tcp_server_socket.close()
            print("[INFO] [AuthServer] Socket TCP do servidor de autenticação fechado.")
        print("[INFO] [AuthServer] Servidor de autenticação encerrado.")

