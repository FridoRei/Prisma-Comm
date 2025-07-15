import subprocess
import socket
from src.core.auth.token_manager import gerar_hash_senha
from src.core.auth.rsa_manager import RSAManager

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

def get_server_public_key(server_ip, auth_port):
    try:
        with socket.create_connection((server_ip, auth_port), timeout=5) as sock:
            print(f"[INFO] [ConnectionManager] Tentando obter chave pública do servidor {server_ip}:{auth_port}...")
            public_key_bytes = sock.recv(2048)
            if not public_key_bytes:
                print(f"[ERROR] [ConnectionManager] Servidor {server_ip}:{auth_port} fechou a conexão ou enviou dados vazios.")
                return None
            
            if public_key_bytes.startswith(b"ERROR:"):
                print(f"[ERROR] [ConnectionManager] Erro reportado pelo servidor ao obter chave pública: {public_key_bytes.decode(errors='ignore')}")
                return None
            
            public_key = RSAManager()._load_key_file(public_key_bytes)
            print(f"[INFO] [ConnectionManager] Chave pública do servidor obtida com sucesso de {server_ip}:{auth_port}.")
            return public_key
    except socket.timeout:
        print(f"[ERROR] [ConnectionManager] Timeout ao tentar obter chave pública do servidor ({server_ip}:{auth_port}).")
    except ConnectionRefusedError:
        print(f"[ERROR] [ConnectionManager] Conexão recusada ao tentar obter chave pública do servidor ({server_ip}:{auth_port}). Verifique se o servidor está ativo.")
    except ValueError as e:
        print(f"[ERROR] [ConnectionManager] Erro ao carregar chave pública recebida de {server_ip}:{auth_port}: {e}. Dados recebidos podem estar corrompidos ou em formato inválido.")
    except Exception as e:
        print(f"[CRITICAL] [ConnectionManager] Erro inesperado ao obter chave pública do servidor {server_ip}:{auth_port}: {e}")
    return None

def verificar_conexao_com_host(ip, porta, password: str):
    if not ip:
        print("[ERROR] [ConnectionManager] Endereço IP do host não fornecido.")
        return False

    print(f"[INFO] [ConnectionManager] Verificando conexão com o host de autenticação {ip}:{porta}...")
    server_public_key = get_server_public_key(ip, porta)
    if not server_public_key:
        print("[ERROR] [ConnectionManager] Não foi possível obter a chave pública do servidor. Autenticação abortada.")
        return False

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(5)
            print(f"[INFO] [ConnectionManager] Gerando hash da senha para envio...")
            try:
                password_hash_para_envio = gerar_hash_senha(password)
            except ValueError as ve:
                print(f"[ERROR] [ConnectionManager] Erro de validação da senha: {ve}")
                return False
            except Exception as e:
                print(f"[CRITICAL] [ConnectionManager] Erro inesperado ao gerar hash da senha para envio: {e}")
                return False

            if not password_hash_para_envio:
                print("[ERROR] [ConnectionManager] Falha ao gerar hash da senha para envio.")
                return False

            print(f"[INFO] [ConnectionManager] Criptografando hash da senha com a chave pública do servidor...")
            encrypted_password_hash = RSAManager.encrypt_with_public_key(
                password_hash_para_envio.encode("utf-8"), server_public_key
            )

            if not encrypted_password_hash:
                print("[ERROR] [ConnectionManager] Erro ao criptografar o hash da senha.")
                return False

            print(f"[INFO] [ConnectionManager] Enviando hash criptografado para {ip}:{porta}...")
            sock.sendto(encrypted_password_hash, (ip, porta))

            print(f"[INFO] [ConnectionManager] Aguardando resposta do servidor...")
            resposta_servidor_bytes, _ = sock.recvfrom(1024)
            
            try:
                resposta_servidor = resposta_servidor_bytes.decode('utf-8').strip()
            except UnicodeDecodeError:
                print(f"[ERROR] [ConnectionManager] Resposta do servidor de {ip}:{porta} não é uma string UTF-8 válida. Conteúdo: {resposta_servidor_bytes.hex()}")
                resposta_servidor = "INVALID_RESPONSE_ENCODING"

            if resposta_servidor == "AUTH_SUCCESS":
                print("[SUCCESS] [ConnectionManager] Autenticação bem-sucedida!")
                return True
            else:
                print(f"[WARNING] [ConnectionManager] Autenticação falhou. Resposta do servidor: '{resposta_servidor}'")
                return False

    except socket.timeout:
        print(f"[ERROR] [ConnectionManager] Timeout na conexão com o host de autenticação ({ip}:{porta}). O servidor não respondeu ao hash da senha UDP.")
    except socket.error as se:
        print(f"[ERROR] [ConnectionManager] Erro de socket ao tentar conectar com {ip}:{porta}: {se}")
    except Exception as e:
        print(f"[CRITICAL] [ConnectionManager] Erro inesperado durante a verificação de conexão com o host de autenticação {ip}:{porta}: {e}")
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
        print(f"[INFO] [ConnectionManager] IPs locais obtidos: {', '.join(gateways) if gateways else 'Nenhum'}")
    except Exception as e:
        print(f"[ERROR] [ConnectionManager] Erro ao obter IPs locais: {e}")
    return gateways if gateways else None

