# src/core/network/connection_manager.py
import subprocess
import socket
from src.core.auth.token_manager import gerar_token
from src.core.auth.rsa_manager import RSAManager

def obter_gateway():
    try:
        result = subprocess.run(["ip", "route"], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if line.startswith("default"):
                partes = line.split()
                if "via" in partes:
                    return partes[partes.index("via") + 1]
    except Exception as e:
        print(f"[ERRO] ao obter gateway: {e}")
    return None

def get_server_public_key(server_ip, auth_port):
    """
    Solicita a chave pública RSA do servidor via TCP.
    """
    try:
        with socket.create_connection((server_ip, auth_port), timeout=5) as sock:
            public_key_bytes = sock.recv(2048)
            if public_key_bytes.startswith(b"ERROR:"):
                print(f"[CLIENTE] Erro ao obter chave pública do servidor: {public_key_bytes.decode()}")
                return None
            
            # Carregar a chave pública a partir dos bytes recebidos
            # RSAManager()._load_key_file agora só espera bytes
            public_key = RSAManager()._load_key_file(public_key_bytes)
            return public_key
    except socket.timeout:
        print(f"[CLIENTE] Timeout ao tentar obter chave pública do servidor ({server_ip}:{auth_port}).")
        return None
    except ConnectionRefusedError:
        print(f"[CLIENTE] Conexão recusada ao tentar obter chave pública do servidor ({server_ip}:{auth_port}).")
        return None
    except Exception as e:
        print(f"[CLIENTE] Erro ao obter chave pública do servidor: {e}")
        return None

def verificar_conexao_com_host(ip, porta):
    if not ip:
        print("Endereço não encontrado.")
        return False

    # 1. Obter a chave pública do servidor (via TCP)
    server_public_key = get_server_public_key(ip, porta)
    if not server_public_key:
        print("[CLIENTE] Não foi possível obter a chave pública do servidor. Autenticação abortada.")
        return False

    try:
        # 2. Enviar token criptografado (via UDP)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(5)

            token_para_envio = gerar_token()
            if not token_para_envio:
                print("[CLIENTE] Erro ao gerar token para envio.")
                return False

            encrypted_token = RSAManager().encrypt_with_public_key(token_para_envio.encode("utf-8"), server_public_key)

            if not encrypted_token:
                print("[CLIENTE] Erro ao criptografar o token.")
                return False

            # Envia o token criptografado para o servidor via UDP
            sock.sendto(encrypted_token, (ip, porta))

            # Recebe a resposta de autenticação do servidor via UDP
            resposta_servidor_bytes, _ = sock.recvfrom(1024)
            resposta_servidor = resposta_servidor_bytes.decode('utf-8').strip()

            if resposta_servidor == "AUTH_SUCCESS":
                print("[CLIENTE] Autenticação bem-sucedida!")
                return True
            else:
                print(f"[CLIENTE] Autenticação falhou. Resposta do servidor: '{resposta_servidor}'")
                return False

    except socket.timeout:
        print(f"[ERRO] Timeout na conexão com o host de autenticação ({ip}:{porta}). O servidor não respondeu ao token UDP.")
    except Exception as e:
        print(f"[ERRO] Falha na conexão com o host de autenticação: {e}")
    return False

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
        print(f"[ERRO] ao obter IPs locais: {e}")
    return gateways if gateways else None
