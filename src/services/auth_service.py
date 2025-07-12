import threading
from src.services.server import run_auth_server

class AuthService:
    def __init__(self, auth_port=20556):
        self.auth_port = auth_port
        self.stop_event = threading.Event()
        self.server_thread = None

    def start_server(self):
        if self.server_thread and self.server_thread.is_alive():
            return

        self.stop_event.clear()
        self.server_thread = threading.Thread(
            target=run_auth_server,
            args=(self.auth_port, self.stop_event),
            daemon=True
        )
        self.server_thread.start()

    def stop_server(self):
        if self.server_thread and self.server_thread.is_alive():
            self.stop_event.set()
            self.server_thread.join(timeout=2)
