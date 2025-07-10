# src/core/utils/log_redirector.py
from PySide6.QtCore import QObject, Signal, Slot
import sys

class ConsoleOutputRedirector(QObject): # Classe para redirecionar a saída do console
    output_written = Signal(str)  # Sinal emitido quando uma nova saída é escrita

    def __init__(self, original_stdout=sys.stdout, original_stderr=sys.stderr): # Inicializa o redirecionador
        super().__init__()
        self._original_stdout = original_stdout # Armazena o stdout original
        self._original_stderr = original_stderr # Armazena o stderr original

    def write(self, text): # Sobrescreve o método write para capturar a saída
        self.output_written.emit(text) # Emite o sinal com o texto capturado
        self._original_stdout.write(text) # Escreve o texto no stdout original (terminal)

    def flush(self): # Sobrescreve o método flush
        self._original_stdout.flush() # Garante que o flush também seja chamado no stdout original

