import subprocess
import socket
import ssl # Adicionar import
from src.core.auth.token_manager import gerar_token, calcular_palavra_base
from src.config.settings import SERVER_CERT, TLS_SERVER_HOSTNAME, TLS_VERIFY_MODE # Adicionar import

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

def verificar_conexao_com_host(porta):
    gateway = obter_gateway()
    if not gateway:
        print("Gateway não encontrado.")
        return False

    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_verify_locations(SERVER_CERT)
    context.verify_mode = getattr(ssl, TLS_VERIFY_MODE, ssl.CERT_REQUIRED) # Usar a configuração do settings

    try:
        with socket.create_connection((gateway, porta), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=TLS_SERVER_HOSTNAME) as ssock: # Envolver o socket com TLS
                token_para_envio = gerar_token()
                if not token_para_envio:
                    print("[CLIENTE] Erro ao gerar token para envio.")
                    return False

                ssock.sendall(token_para_envio.encode('utf-8'))

                resposta_servidor = ssock.recv(1024).decode('utf-8').strip()

                if resposta_servidor == "AUTH_SUCCESS":
                    return True
                else:
                    print(f"[CLIENTE] Autenticação falhou: {resposta_servidor}")
                    return False

    except ssl.SSLError as e: # Capturar erros específicos de SSL
        print(f"[ERRO] Erro SSL na conexão com o host de autenticação ({gateway}:{porta}): {e}")
    except socket.timeout:
        print(f"[ERRO] Timeout na conexão com o host de autenticação ({gateway}:{porta}).")
    except ConnectionRefusedError:
        print(f"[ERRO] Conexão recusada pelo host de autenticação ({gateway}:{porta}). O servidor pode não estar ativo ou a porta está bloqueada.")
    except Exception as e:
        print(f"[ERRO] Falha na conexão com o host de autenticação: {e}")
    return False
