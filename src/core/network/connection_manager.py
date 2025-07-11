import subprocess
import socket
from src.core.auth.token_manager import gerar_token, calcular_palavra_base 

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
        return False, None

    try:
        with socket.create_connection((gateway, porta), timeout=5) as sock: 

            token_para_envio = gerar_token() 
            if not token_para_envio:
                print("[CLIENTE] Erro ao gerar token para envio.")
                return False, None

            sock.sendall(token_para_envio.encode('utf-8')) 

            resposta_servidor_raw = sock.recv(1024).decode('utf-8').strip()
            
            partes_resposta = resposta_servidor_raw.split(':', 1)
            status = partes_resposta[0]
            ip_autenticado = partes_resposta[1] if len(partes_resposta) > 1 else None

            if resposta_servidor == "AUTH_SUCCESS": 
                print(f"[CLIENTE] Autenticação bem-sucedida com o servidor de autenticação. IP autenticado: {ip_autenticado}")
                return True, ip_autenticado
            else: 
                print(f"[CLIENTE] Autenticação falhou: {resposta_servidor}")
                return False, None 

    except socket.timeout:
        print(f"[ERRO] Timeout na conexão com o host de autenticação ({gateway}:{porta}).") 
    except ConnectionRefusedError:
        print(f"[ERRO] Conexão recusada pelo host de autenticação ({gateway}:{porta}). O servidor pode não estar ativo ou a porta está bloqueada.")
    except Exception as e:
        print(f"[ERRO] Falha na conexão com o host de autenticação: {e}") 
    return False, None

