import bcrypt
import re

def validar_senha_forte(password: str) -> bool:
    """
    Valida se a senha atende aos critérios de segurança:
    - Mínimo de 12 caracteres.
    - Contém letras maiúsculas, minúsculas, números e caracteres especiais permitidos.
    Caracteres especiais permitidos: @, #, $, %, &, ç
    """
    if len(password) < 12:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"\d", password):
        return False
    if not re.search(r"[@#$%&ç]", password):
        return False
    if not re.fullmatch(r"[A-Za-z0-9@#$%&ç]+", password):
        return False

    return True

def gerar_hash_senha(password: str) -> str:
    """
    Gera um hash bcrypt da senha fornecida.
    """
    try:
        if not validar_senha_forte(password):
            raise ValueError("A senha não atende aos requisitos de segurança.")
        salt_aleatorio = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode("utf-8"), salt_aleatorio)
        return hashed_password.decode("utf-8")
    except ValueError as ve:
        print(f"[ERROR] [TokenManager] Erro de validação da senha: {ve}")
        raise
    except Exception as e:
        print(f"[CRITICAL] [TokenManager] Erro inesperado ao gerar hash da senha: {e}")
        return None

def verificar_senha(password: str, hashed_password: str) -> bool:
    """
    Verifica se a senha fornecida corresponde ao hash bcrypt.
    """
    try:
        result = bcrypt.checkpw(password.encode(), hashed_password.encode("utf-8"))
        return result
    except Exception as e:
        print(f"[ERROR] [TokenManager] Erro ao verificar senha: {e}")
        return False

