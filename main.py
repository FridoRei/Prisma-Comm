import sys
import warnings
from PySide6.QtWidgets import QApplication
from src.gui.main_window import MainWindow
from src.core.utils.log_redirector import ConsoleOutputRedirector # Nova importação

def formatar_warning(mensagem, categoria, filename, lineno, file=None, line=None):
    if categoria == RuntimeWarning:
        print(f"\n[AVISO - RuntimeWarning]")
        print(f"→ Arquivo: {filename}")
        print(f"→ Linha: {lineno}")
        print(f"→ Mensagem: {mensagem}\n")
    else:
        warnings._showwarnmsg_impl(warnings.WarningMessage(mensagem, categoria, filename, lineno, file, line))

warnings.showwarning = formatar_warning

if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = MainWindow()

    # Redireciona stdout/stderr para o log da GUI
    original_stdout = sys.stdout
    original_stderr = sys.stderr
    console_redirector = ConsoleOutputRedirector(original_stdout, original_stderr)
    console_redirector.output_written.connect(win.append_log_message)
    sys.stdout = console_redirector
    sys.stderr = console_redirector

    win.show()
    sys.exit(app.exec())

