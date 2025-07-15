import time
import threading
from collections import defaultdict

class DoSDetector:
    """ Mecanismo para detectar e mitigar tentativas de ataque DoS baseado em limitação de taxa por endereço IP."""
    def __init__(self,
                 request_limit: int = 2,
                 time_window: int = 1,
                 block_duration: int = 300):
        self.request_limit = request_limit
        self.time_window = time_window
        self.block_duration = block_duration

        self.ip_requests = defaultdict(list)
        self.blocked_ips = {}

        self.lock = threading.Lock()
        self._running = True
        self.cleanup_thread = threading.Thread(target=self._cleanup_old_requests, daemon=True)
        self.cleanup_thread.start()
        print(f"[INFO] [DoSDetector] Detector de DoS inicializado: Limite={request_limit} req/{time_window}s, Bloqueio={block_duration}s.")

    def _cleanup_old_requests(self):
        """ Thread interna para limpar requisições antigas e IPs bloqueados expirados. """
        while self._running:
            current_time = time.time()
            with self.lock:
                ips_to_remove_from_requests = []
                for ip, timestamps in self.ip_requests.items():
                    self.ip_requests[ip] = [ts for ts in timestamps if ts > current_time - self.time_window]
                    if not self.ip_requests[ip]:
                        ips_to_remove_from_requests.append(ip)
                for ip in ips_to_remove_from_requests:
                    del self.ip_requests[ip]

                ips_to_unblock = []
                for ip, unblock_time in self.blocked_ips.items():
                    if current_time > unblock_time:
                        ips_to_unblock.append(ip)
                for ip in ips_to_unblock:
                    del self.blocked_ips[ip]
                    print(f"[INFO] [DoSDetector] IP {ip} desbloqueado após {self.block_duration}s.")
            time.sleep(1) 

    def check_and_record(self, ip_address: str) -> bool:
        """
        Verifica se o IP está bloqueado e registra uma nova requisição.

        Args:
            ip_address (str): O endereço IP do cliente.

        Returns:
            bool: True se a requisição for permitida, False se o IP estiver bloqueado
                  ou exceder o limite e for bloqueado.
        """
        current_time = time.time()
        with self.lock:
            if ip_address in self.blocked_ips:
                if current_time < self.blocked_ips[ip_address]:
                    print(f"[WARNING] [DoSDetector] Requisição de IP bloqueado: {ip_address}")
                    return False
                else:
                    del self.blocked_ips[ip_address]
                    print(f"[INFO] [DoSDetector] IP {ip_address} desbloqueado (expiração detectada no check).")

            self.ip_requests[ip_address] = [ts for ts in self.ip_requests[ip_address] if ts > current_time - self.time_window]

            self.ip_requests[ip_address].append(current_time)

            if len(self.ip_requests[ip_address]) > self.request_limit:
                self.blocked_ips[ip_address] = current_time + self.block_duration
                print(f"[ALERT] [DoSDetector] IP {ip_address} excedeu o limite de {self.request_limit} requisições em {self.time_window}s. Bloqueando por {self.block_duration}s.")
                self.ip_requests[ip_address].clear()
                return False
            
            return True

    def stop(self):
        """
        Para a thread de limpeza do detector de DoS.
        """
        self._running = False
        if self.cleanup_thread.is_alive():
            self.cleanup_thread.join(timeout=2)
            if self.cleanup_thread.is_alive():
                print("[WARNING] [DoSDetector] Thread de limpeza não encerrou em tempo.")
        print("[INFO] [DoSDetector] Detector de DoS parado.")

