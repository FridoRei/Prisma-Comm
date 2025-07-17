import threading

clientes_lock = threading.Lock()
handlers = []

client_aes_keys = {}
client_aes_keys_lock = threading.Lock()
temp_rsa_managers = {}
temp_rsa_managers_lock = threading.Lock()
connected_users = {}
connected_users_lock = threading.Lock()

authenticated_ips = {}
authenticated_ips_lock = threading.Lock()

