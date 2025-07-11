import os
from pathlib import Path

DEFAULT_USERNAME = "Usuário"
DEFAULT_AUTH_PORT = 20556
DEFAULT_COMM_PORT = 20557


DEFAULT_HOTSPOT_SSID = "SecureComunication"
DEFAULT_HOTSPOT_PASSWORD = "12345678" 

SALT_FIXO = b"$2b$12$mB5zHx9pQoLkgYvLfE3M1O"

BASE_DIR = Path(__file__).resolve().parent.parent  
CERTS_DIR = os.path.join(BASE_DIR, 'core', 'auth', 'certs')

SERVER_CERT = os.path.join(CERTS_DIR, 'server.crt')
SERVER_KEY = os.path.join(CERTS_DIR, 'server.key')
TLS_SERVER_HOSTNAME = "localhost"  
TLS_VERIFY_MODE = "CERT_REQUIRED"