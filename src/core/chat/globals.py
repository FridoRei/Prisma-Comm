import threading

clientes_lock = threading.Lock()
handlers = [] 
authenticated_ips = set() 
authenticated_ips_lock = threading.Lock()
client_aes_keys = {}
client_aes_keys_lock = threading.Lock()
temp_rsa_managers = {}
temp_rsa_managers_lock = threading.Lock()
connected_users = {}
connected_users_lock = threading.Lock()