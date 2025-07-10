from PySide6.QtCore import QObject, Signal, Slot
import sys

class ConsoleOutputRedirector(QObject): 
    output_written = Signal(str)  

    def __init__(self, original_stdout=sys.stdout, original_stderr=sys.stderr): 
        super().__init__()
        self._original_stdout = original_stdout 
        self._original_stderr = original_stderr 

    def write(self, text): 
        self.output_written.emit(text) 
        self._original_stdout.write(text) 

    def flush(self): 
        self._original_stdout.flush() 

