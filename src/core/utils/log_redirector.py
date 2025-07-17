from PySide6.QtCore import QObject, Signal, Slot
import sys
import re 

class ConsoleOutputRedirector(QObject):
    output_written = Signal(str)

    def __init__(self, original_stdout=sys.stdout, original_stderr=sys.stderr):
        super().__init__()
        self._original_stdout = original_stdout
        self._original_stderr = original_stderr
        self.log_level_pattern = re.compile(r"^\[(INFO|ERROR|WARNING|CRITICAL|DEBUG)\]")

    def write(self, text):
        match = self.log_level_pattern.match(text)
        if match:
            log_level = match.group(1) 
            self.output_written.emit(f"<span class='{log_level}'>{text}</span>")
        else:
            self.output_written.emit(text)

        self._original_stdout.write(text) 

    def flush(self):
        self._original_stdout.flush()