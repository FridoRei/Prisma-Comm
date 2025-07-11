from cryptography.hazmat.primitives.serialization import load_pem_parameters
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import os

DH_PARAMS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'secret', 'dhparams.pem')

_dh_parameters = None

def load_dh_parameters():
    global _dh_parameters
    if _dh_parameters is None:
        try:
            with open(DH_PARAMS_FILE, "rb") as f:
                _dh_parameters = load_pem_parameters(f.read(), backend=default_backend())
            print(f"[DH_PARAMS] Parâmetros DH carregados de: {DH_PARAMS_FILE}")
        except FileNotFoundError:
            print(f"[ERRO] Arquivo de parâmetros DH não encontrado: {DH_PARAMS_FILE}")
            print("[ERRO] Por favor, gere-o com 'openssl dhparam -out dhparams.pem 3072' e coloque-o na raiz do projeto.")
            _dh_parameters = None 
            raise 
        except Exception as e:
            print(f"[ERRO] Erro ao carregar parâmetros DH: {e}")
            _dh_parameters = None
            raise
    return _dh_parameters

