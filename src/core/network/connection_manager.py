import subprocess
import socket
import time 
from src.core.auth.token_manager import gerar_hash_senha
from src.core.crypto.ecc_manager import ECCManager 
from src.core.crypto.aes_manager import AESManager 
from cryptography.hazmat.primitives.asymmetric import ed25519
import hashlib
    
def is_utf8_valid(data: bytes) -> bool:
    try:
        data.decode('utf-8')
        return True
    except UnicodeDecodeError:
        return False

def obter_gateway():
    try:
        result = subprocess.run(["ip", "route"], capture_output=True, text=True, check=True)
        for line in result.stdout.splitlines():
            if line.startswith("default"):
                partes = line.split()
                if "via" in partes:
                    print(f"[INFO] [ConnectionManager] Gateway obtido: {partes[partes.index('via') + 1]}")
                    return partes[partes.index("via") + 1]
        print("[WARNING] [ConnectionManager] Gateway não encontrado na saída do comando 'ip route'.")
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] [ConnectionManager] Erro ao executar 'ip route': {e}")
    except Exception as e:
        print(f"[ERROR] [ConnectionManager] Erro inesperado ao obter gateway: {e}")
    return None

def obter_gateway_generico():
    gateways = []
    try:
        hostname = socket.gethostname()
        info = socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_STREAM, 0, socket.AI_PASSIVE)
        for res in info:
            ip_address = res[4][0]
            if ip_address != '127.0.0.1' and ip_address not in gateways:
                gateways.append(ip_address)
    except Exception as e:
        print(f"[ERROR] [ConnectionManager] Erro ao obter IPs locais: {e}")
    return gateways if gateways else None

def perform_ecc_auth_handshake(server_ip: str, auth_port: int, password: str, client_ed25519_public_key_bytes: bytes, ecc_manager: ECCManager, ecc_handshake_timeout: int, password_response_timeout: int) -> tuple[str, bytes]:
    """
    Realiza o handshake ECC completo e a autenticação da senha com o servidor.
    Retorna uma tupla: (status: str, session_aes_key: bytes ou None)
    Status pode ser: "AUTH_SUCCESS", "AUTH_FAILURE_PASSWORD", "AUTH_FAILURE_TIMEOUT", etc.
    """
    client_socket = None
    temp_aes_manager = None
    session_aes_key = None

    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.settimeout(ecc_handshake_timeout)
        client_socket.connect((server_ip, auth_port))
        print(f"[INFO] [ConnectionManager] Conectado ao servidor de autenticação {server_ip}:{auth_port}.")

        server_handshake_data_b64 = client_socket.recv(4096).decode('utf-8')
        parts = server_handshake_data_b64.split('|')
        if len(parts) != 2:
            raise ValueError(f"Formato de handshake do servidor inválido. Dados recebidos: {server_handshake_data_b64[:50]}...")

        server_x25519_public_b64 = parts[0]
        server_signature_b64 = parts[1]

        server_x25519_public_bytes = ECCManager.base64_to_bytes(server_x25519_public_b64)
        server_signature_bytes = AESManager.base64_to_bytes(server_signature_b64)

        if not ECCManager.verify_signature(client_ed25519_public_key_bytes, server_x25519_public_bytes, server_signature_bytes):
            raise Exception("Erro de segurança: Falha na verificação da autenticidade do servidor. A conexão pode não ser segura.")
        print(f"[INFO] [ConnectionManager] Assinatura do servidor verificada com sucesso.")

        ecc_manager.generate_x25519_keys()
        client_x25519_public_bytes = ecc_manager.get_x25519_public_key_bytes()
        response_data = f"{ECCManager.bytes_to_base64(client_x25519_public_bytes)}"
        client_socket.sendall(response_data.encode('utf-8'))

        derived_temp_aes_key = ecc_manager.derive_shared_key(server_x25519_public_bytes)
        temp_aes_manager = AESManager(derived_temp_aes_key)

        encrypted_handshake_response_b64 = client_socket.recv(1024).decode('utf-8')
        encrypted_parts = encrypted_handshake_response_b64.split('|')
        if len(encrypted_parts) != 3:
            raise Exception(f"Erro de comunicação: Formato de resposta de segurança inválido.")
        nonce = AESManager.base64_to_bytes(encrypted_parts[0])
        ciphertext = AESManager.base64_to_bytes(encrypted_parts[1])
        tag = AESManager.base64_to_bytes(encrypted_parts[2])
        handshake_response = temp_aes_manager.decrypt(nonce, ciphertext, tag)

        if handshake_response != "ECC_HANDSHAKE_SUCCESS":
            raise Exception(f"Erro de segurança: Handshake de criptografia falhou. Resposta: {handshake_response}")
        print(f"[SUCCESS] [ConnectionManager] Handshake concluído com sucesso.")

        try:
            password_hash_para_envio = gerar_hash_senha(password)
        except ValueError as ve:
            print(f"[ERROR] [ConnectionManager] Erro de validação da senha: {ve}")
            return "AUTH_FAILURE_INVALID_PASSWORD_FORMAT", None
        except Exception as e:
            print(f"[CRITICAL] [ConnectionManager] Erro inesperado ao gerar hash da senha para envio: {e}")
            return "AUTH_FAILURE_INTERNAL_ERROR", None

        nonce_pass, cipher_pass, tag_pass = temp_aes_manager.encrypt(password_hash_para_envio)
        encrypted_password_hash_b64 = f"{AESManager.bytes_to_base64(nonce_pass)}|{AESManager.bytes_to_base64(cipher_pass)}|{AESManager.bytes_to_base64(tag_pass)}"
        client_socket.sendall(encrypted_password_hash_b64.encode('utf-8'))

        client_socket.settimeout(password_response_timeout) 
        encrypted_session_key_b64 = client_socket.recv(4096).decode('utf-8')
        if not encrypted_session_key_b64:
            return "AUTH_FAILURE_NO_SESSION_KEY", None

        if encrypted_session_key_b64.startswith("AUTH_FAILURE"):
            return encrypted_session_key_b64, None 

        parts_key = encrypted_session_key_b64.split('|')
        if len(parts_key) != 3:
            raise ValueError("Formato da chave de sessão criptografada inválido.")

        nonce_key = AESManager.base64_to_bytes(parts_key[0])
        cipher_key = AESManager.base64_to_bytes(parts_key[1])
        tag_key = AESManager.base64_to_bytes(parts_key[2])

        decrypted_session_key_b64 = temp_aes_manager.decrypt(nonce_key, cipher_key, tag_key)
        session_aes_key = AESManager.base64_to_bytes(decrypted_session_key_b64)
        print(f"[DEBUG] [ConnectionManager] Cliente recebeu session_aes_key (hash): {hashlib.sha256(session_aes_key).hexdigest()}")

        session_aes_manager_for_client = AESManager(session_aes_key)
        encrypted_confirmation_b64 = client_socket.recv(4096).decode('utf-8')
        if not encrypted_confirmation_b64:
            return "AUTH_FAILURE_NO_CONFIRMATION", None

        parts_conf = encrypted_confirmation_b64.split('|')
        if len(parts_conf) != 3:
            raise ValueError("Formato da mensagem de confirmação inválido.")

        nonce_conf = AESManager.base64_to_bytes(parts_conf[0])
        cipher_conf = AESManager.base64_to_bytes(parts_conf[1])
        tag_conf = AESManager.base64_to_bytes(parts_conf[2])

        decrypted_confirmation_message = session_aes_manager_for_client.decrypt(nonce_conf, cipher_conf, tag_conf)

        nonce_client_conf, cipher_client_conf, tag_client_conf = session_aes_manager_for_client.encrypt(decrypted_confirmation_message)
        encrypted_client_confirmation_b64 = f"{AESManager.bytes_to_base64(nonce_client_conf)}|{AESManager.bytes_to_base64(cipher_client_conf)}|{AESManager.bytes_to_base64(tag_client_conf)}"
        client_socket.sendall(encrypted_client_confirmation_b64.encode('utf-8'))

        final_status_b64 = client_socket.recv(1024).decode('utf-8')
        if not final_status_b64:
            return "AUTH_FAILURE_NO_FINAL_STATUS", None

        parts_final = final_status_b64.split('|')
        if len(parts_final) != 3:
            raise ValueError("Formato do status final inválido.")

        nonce_final = AESManager.base64_to_bytes(parts_final[0])
        cipher_final = AESManager.base64_to_bytes(parts_final[1])
        tag_final = AESManager.base64_to_bytes(parts_final[2])

        final_status = session_aes_manager_for_client.decrypt(nonce_final, cipher_final, tag_final)

        if final_status == "AUTH_SUCCESS":
            return "AUTH_SUCCESS", session_aes_key
        else:
            print(f"[WARNING] [ConnectionManager] Autenticação FALHOU. Status: {final_status}")
            return final_status, None

    except socket.timeout:
        print(f"[ERROR] [ConnectionManager] Timeout durante o processo de autenticação.")
        return "AUTH_FAILURE_TIMEOUT", None
    except ConnectionRefusedError:
        print(f"[ERROR] [ConnectionManager] Conexão recusada pelo servidor {server_ip}:{auth_port}. Verifique se o servidor está ativo.")
        return "AUTH_FAILURE_CONNECTION_REFUSED", None
    except ValueError as e:
        print(f"[ERROR] [ConnectionManager] Erro de formato de dados ou validação durante a autenticação: {e}")
        return f"AUTH_FAILURE_DATA_ERROR: {e}", None
    except Exception as e:
        print(f"[CRITICAL] [ConnectionManager] Erro inesperado durante a autenticação: {e}")
        return f"AUTH_FAILURE_UNEXPECTED_ERROR: {e}", None
    finally:
        ecc_manager.clear_x25519_keys() 
        if client_socket:
            try:
                client_socket.close()
            except Exception as e:
                print(f"[ERROR] [ConnectionManager] Erro ao fechar socket do cliente: {e}")