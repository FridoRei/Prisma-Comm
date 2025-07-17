class RequestLimiter:
    """
    Gerencia limites de tamanho para requisições recebidas.
    """
    def __init__(self, max_length: int = 600):
        self.max_length = max_length
        print(f"[INFO] [RequestLimiter] Limite máximo de requisição definido para {self.max_length} bytes.")

    def is_request_too_large(self, data: bytes) -> bool:
        """
        Verifica se o tamanho dos dados da requisição excede o limite máximo.
        Retorna True se for muito grande, False caso contrário.
        """
        if len(data) > self.max_length:
            print(f"[WARNING] [RequestLimiter] Requisição excedeu o limite de tamanho ({len(data)} bytes > {self.max_length} bytes).")
            return True
        return False

