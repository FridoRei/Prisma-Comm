# src/services/server.py
import socket
import subprocess
import os
import signal
import time
import sys # Importar sys para ler argumentos de linha de comando
from src.core.auth.token_manager import gerar_token, validar_token, calcular_palavra_base # Nova importação

HOST = '0.0.0.0'
# A porta agora será lida dos argumentos de linha de comando
PORT = 20556 # Valor padrão, será sobrescrito se um argumento for fornecido

# Se um argumento de porta for fornecido, use-o
if len(sys.argv) > 1:
    try:
        PORT = int(sys.argv[1])
    except ValueError:
        print(f"[SERVIDOR] Aviso: Porta inválida fornecida '{sys.argv[1]}'. Usando porta padrão {PORT}.")

# Flag para controlar o loop principal do servidor
running = True

# Handler para o sinal SIGTERM
def signal_handler(signum, frame):
    global running
    print(f"\n[SERVIDOR] Sinal {signum} recebido. Encerrando servidor de autenticação...")
    running = False

# Registrar o handler para SIGTERM
signal.signal(signal.SIGTERM, signal_handler)

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

try:
    server_socket.bind((HOST, PORT))
    server_socket.listen(1)
    server_socket.settimeout(1.0) # Define um timeout para o accept para poder verificar a flag 'running'

    print(f"Esperando por uma conexão na porta {PORT}...")

    while running: # Loop agora controlado pela flag 'running'
        conn = None # Inicializa conn para garantir que esteja definido no finally
        try:
            conn, addr = server_socket.accept()
            print(f"\nConexão recebida de {addr}")
            resposta = "AUTH_FAILURE"

            try:
                # 1. Servidor recebe o token (hash bcrypt) do cliente
                token_recebido_bytes = conn.recv(1024)
                if not token_recebido_bytes:
                    print("[SERVIDOR] Cliente desconectou antes de enviar o token.")
                    continue

                token_recebido = token_recebido_bytes.decode('utf-8').strip()
                print(f"[SERVIDOR] Token (hash bcrypt) recebido do cliente: {token_recebido}")

                # 2. Servidor gera sua própria palavra base (para depuração)
                palavra_base_local_servidor = calcular_palavra_base()
                print(f"[SERVIDOR] Palavra base calculada pelo servidor (para depuração): {palavra_base_local_servidor}")

                # 3. Servidor valida o token recebido usando a palavra base local
                if validar_token(token_recebido, addr):
                    print("[SERVIDOR] Token VALIDADO com sucesso!")
                    resposta = "AUTH_SUCCESS"
                else:
                    print("[SERVIDOR] Token INVÁLIDO. Desencontro ou palavra base incorreta.")
                    resposta = "AUTH_FAILURE_INVALID_TOKEN"

            except socket.timeout:
                # Este timeout é para o recv, não para o accept.
                # Se o cliente conectar mas não enviar dados, ele pode ocorrer.
                print("[SERVIDOR] Timeout ao receber token do cliente.")
                resposta = "AUTH_FAILURE_TIMEOUT"
            except Exception as e:
                print(f"[SERVIDOR] Erro ao processar conexão de autenticação: {e}")
                resposta = f"AUTH_FAILURE_ERROR: {str(e)}"
            finally:
                if conn: # Garante que conn existe antes de tentar fechar
                    # 4. Servidor envia a resposta de volta ao cliente
                    conn.sendall(resposta.encode('utf-8'))
                    conn.close()
                    print(f"[SERVIDOR] Resposta enviada ao cliente {addr}: {resposta}")

        except socket.timeout:
            # Este timeout é do server_socket.accept(), permite que o loop verifique 'running'
            pass
        except Exception as e:
            if running: # Só imprime erro se não estiver em processo de desligamento
                print(f"[SERVIDOR] Erro ao aceitar conexão: {e}")

except Exception as e:
    print(f"[SERVIDOR] Erro fatal no servidor: {e}")
finally:
    server_socket.close()
    print("[SERVIDOR] Servidor de autenticação encerrado.")

