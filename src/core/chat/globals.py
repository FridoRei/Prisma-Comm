import threading

clientes_lock = threading.Lock()
handlers = [] 
authenticated_ips = set() 
authenticated_ips_lock = threading.Lock()