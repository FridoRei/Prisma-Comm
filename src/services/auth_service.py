import os
import subprocess
import signal # Importar signal para lidar com o encerramento
import sys
from src.config.settings import DEFAULT_AUTH_PORT 

class AuthService:
    def __init__(self, auth_port=DEFAULT_AUTH_PORT):
        self.auth_port = auth_port
        self.auth_server_process = None

    def start_server(self):
        # Verifica se o processo já está rodando e ainda ativo
        if self.auth_server_process and self.auth_server_process.poll() is None:
            print("[P2P-COM] Servidor de autenticação já está rodando.")
            return
            
        try:
            # Constrói o caminho absoluto para server.py
            # Assumimos que server.py está na mesma pasta que auth_service.py
            current_dir = os.path.dirname(os.path.abspath(__file__))
            server_script_path = os.path.join(current_dir, 'server.py')
            
            # Verifica se o script existe antes de tentar executá-lo
            if not os.path.exists(server_script_path):
                raise FileNotFoundError(f"O script do servidor 'server.py' não foi encontrado em: {server_script_path}")

            print(f"[P2P-COM] Tentando iniciar o script do servidor: {server_script_path}")
            
            # Inicia o server.py como um subprocesso
            # stdout e stderr são redirecionados para pipes, mas não são lidos imediatamente
            # preexec_fn=os.setsid é usado para criar um novo grupo de processo (Unix-like)
            # o que ajuda a desvincular o subprocesso do processo pai.
            self.auth_server_process = subprocess.Popen(
                [sys.executable, server_script_path, str(self.auth_port)],
                stdout=subprocess.PIPE, # Redireciona stdout para um pipe
                stderr=subprocess.PIPE, # Redireciona stderr para um pipe
                preexec_fn=os.setsid    # Cria um novo grupo de processo (Unix-like)
                                        # Para Windows, considere 'creationflags=subprocess.CREATE_NEW_PROCESS_GROUP'
                                        # se precisar de desvinculação similar.
            )
            print(f"[P2P-COM] Servidor de autenticação iniciado em segundo plano na porta {self.auth_port}.")

            # Nota: Não estamos lendo stdout/stderr aqui imediatamente com .communicate()
            # para que o processo continue rodando em segundo plano sem bloquear.
            # A saída será capturada pelos pipes e pode ser lida posteriormente se necessário,
            # ou simplesmente ignorada se o objetivo é apenas que o servidor rode.

        except FileNotFoundError as e:
            print(f"[P2P-COM] ERRO: {e}")
            self.auth_server_process = None # Garante que o processo não seja referenciado se não foi iniciado
        except Exception as e:
            print(f"[P2P-COM] Erro ao iniciar servidor de autenticação: {e}")
            # Se o processo foi criado mas falhou logo em seguida, tente encerrá-lo
            if self.auth_server_process and self.auth_server_process.poll() is None:
                try:
                    # Tenta encerrar o grupo de processo para garantir que não fiquem processos órfãos
                    os.killpg(os.getpgid(self.auth_server_process.pid), signal.SIGTERM)
                except Exception as kill_e:
                    print(f"[P2P-COM] Erro ao tentar encerrar processo falho: {kill_e}")
            self.auth_server_process = None # Garante que o processo não seja referenciado se houve erro
            raise # Re-lança a exceção para tratamento superior na AppService/MainWindow

    def stop_server(self):
        # Verifica se o processo existe e ainda está rodando
        if self.auth_server_process and self.auth_server_process.poll() is None:
            try:
                # Envia SIGTERM para o grupo de processo para garantir que todos os filhos sejam encerrados
                # (importante se o server.py criar threads ou outros subprocessos)
                os.killpg(os.getpgid(self.auth_server_process.pid), signal.SIGTERM)
                # Espera um pouco para o processo terminar, com timeout
                self.auth_server_process.wait(timeout=5)
                print("[P2P-COM] Servidor de autenticação encerrado.")
            except Exception as e:
                print(f"[P2P-COM] Erro ao encerrar servidor de autenticação: {e}")
        self.auth_server_process = None # Limpa a referência ao processo
