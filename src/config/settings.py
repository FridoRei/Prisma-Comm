# src/config/settings.py

# Configurações de Usuário e Portas
DEFAULT_USERNAME = "Usuário"
DEFAULT_AUTH_PORT = 20556
DEFAULT_COMM_PORT = 20557

# Configurações de Hotspot
DEFAULT_HOTSPOT_SSID = "SecureComunication"
DEFAULT_HOTSPOT_PASSWORD = "12345678" # ATENÇÃO: Em um ambiente real, senhas não devem ser hardcoded.

# Configurações de Autenticação (SALT_FIXO)
# ATENÇÃO: O uso de um SALT_FIXO é uma VULNERABILIDADE DE SEGURANÇA.
# Em um sistema de produção, o salt deve ser gerado aleatoriamente por hash e armazenado junto com o hash.
# A palavra base também deve ser mais robusta e não baseada apenas em tempo.
SALT_FIXO = b"$2b$12$mB5zHx9pQoLkgYvLfE3M1O"

