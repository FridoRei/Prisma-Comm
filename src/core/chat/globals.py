import threading

clientes_lock = threading.Lock()
handlers = [] 
clientes_autorizados = set()
autorizados_lock = threading.Lock()