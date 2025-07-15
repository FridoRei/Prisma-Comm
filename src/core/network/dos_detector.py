import time
import threading
from collections import defaultdict

class DoSDetector:
    """ Mecanismo para detectar e mitigar tentativas de ataque DoS baseado em limitação de taxa por endereço IP."""
    def __init__(self, request_limit: int = 2, time_window: int = 1, block_duration: int = 300):
        print(f"[INFO] DoSDetector initialized with limit: {request_limit}, window: {time_window}, block duration: {block_duration}")
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
        current_time = time.time()
        with self.lock:
            print(f"[DEBUG] Checking IP: {ip_address} at {current_time}")
            if ip_address in self.blocked_ips:
                if current_time < self.blocked_ips[ip_address]:
                    print(f"[DEBUG] IP {ip_address} is currently blocked until {self.blocked_ips[ip_address]}")
                    return False
                else:
                    print(f"[DEBUG] IP {ip_address} block expired. Unblocking.")
                    del self.blocked_ips[ip_address]

            # Filter old requests
            self.ip_requests[ip_address] = [ts for ts in self.ip_requests[ip_address] if ts > current_time - self.time_window]
            print(f"[DEBUG] IP {ip_address} requests in window: {len(self.ip_requests[ip_address])}")

            self.ip_requests[ip_address].append(current_time)
            print(f"[DEBUG] IP {ip_address} new request count: {len(self.ip_requests[ip_address])}, limit: {self.request_limit}")

            if len(self.ip_requests[ip_address]) > self.request_limit:
                self.blocked_ips[ip_address] = current_time + self.block_duration
                print(f"[DEBUG] IP {ip_address} EXCEEDED LIMIT! Blocking until {self.blocked_ips[ip_address]}")
                self.ip_requests[ip_address].clear()
                return False

            print(f"[DEBUG] IP {ip_address} request allowed.")
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

