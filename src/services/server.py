# src/services/server.py
import socket
import subprocess
import os
import signal
import time
import sys
from src.core.auth.token_manager import gerar_token, validar_token, calcular_palavra_base
from src.core.chat.globals import clientes_autorizados, autorizados_lock # Importar a nova lista e o lock

HOST = '0.0.0.0'
PORT = 20556

if len(sys.argv) > 1:
    try:
        PORT = int(sys.argv[1])
    except ValueError:
        print(f"[SERVIDOR] Aviso: Porta inválida fornecida '{sys.argv[1]}'. Usando porta padrão {PORT}.")

running = True

def signal_handler(signum, frame):
    global running
    print(f"\n[SERVIDOR] Sinal {signum} recebido. Encerrando servidor de autenticação...")
    running = False

signal.signal(signal.SIGTERM, signal_handler)

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

try:
    server_socket.bind((HOST, PORT))
    server_socket.listen(1)
    server_socket.settimeout(1.0)

    print(f"Esperando por uma conexão na porta {PORT}...")

    while running:
        conn = None
        try:
            conn, addr = server_socket.accept()
            client_ip = addr[0] # Obter o IP do cliente
            print(f"\nConexão recebida de {addr}")
            resposta = "AUTH_FAILURE"

            try:
                token_recebido_bytes = conn.recv(1024)
                if not token_recebido_bytes:
                    print("[SERVIDOR] Cliente desconectou antes de enviar o token.")
                    continue

                token_recebido = token_recebido_bytes.decode('utf-8').strip()
                print(f"[SERVIDOR] Token (hash bcrypt) recebido do cliente: {token_recebido}")

                palavra_base_local_servidor = calcular_palavra_base()
                print(f"[SERVIDOR] Palavra base calculada pelo servidor (para depuração): {palavra_base_local_servidor}")

                if validar_token(token_recebido, addr):
                    print("[SERVIDOR] Token VALIDADO com sucesso!")
                    resposta = "AUTH_SUCCESS"
                    # Adicionar o IP do cliente à lista de autorizados
                    with autorizados_lock:
                        clientes_autorizados.add(client_ip)
                    print(f"[SERVIDOR] Cliente {client_ip} adicionado à lista de autorizados.")
                else:
                    print("[SERVIDOR] Token INVÁLIDO. Desencontro ou palavra base incorreta.")
                    resposta = "AUTH_FAILURE_INVALID_TOKEN"

            except socket.timeout:
                print("[SERVIDOR] Timeout ao receber token do cliente.")
                resposta = "AUTH_FAILURE_TIMEOUT"
            except Exception as e:
                print(f"[SERVIDOR] Erro ao processar conexão de autenticação: {e}")
                resposta = f"AUTH_FAILURE_ERROR: {str(e)}"
            finally:
                if conn:
                    conn.sendall(resposta.encode('utf-8'))
                    conn.close()
                    print(f"[SERVIDOR] Resposta enviada ao cliente {addr}: {resposta}")

        except socket.timeout:
            pass
        except Exception as e:
            if running:
                print(f"[SERVIDOR] Erro ao aceitar conexão: {e}")

except Exception as e:
    print(f"[SERVIDOR] Erro fatal no servidor: {e}")
finally:
    server_socket.close()
    print("[SERVIDOR] Servidor de autenticação encerrado.")
