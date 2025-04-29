"""
@file main.py
@brief Main entry point for launching the PAdES signing application with GUI.
"""
import sys
from pathlib import Path
from PySide6.QtWidgets import QApplication
from icecream import ic

current_file = Path(__file__).resolve()
project_root = current_file.parents[3]
sys.path.append(str(project_root))

from src.app.frontend.windows import MainWindow

if __name__ == "__main__":
    """
    @brief Configures debugging, initializes the QApplication, creates the main window, and starts the event loop.
    """
    ic.configureOutput(prefix="> debug-info: ", includeContext=True)

    app = QApplication(sys.argv)

    window = MainWindow()
    window.show()

    sys.exit(app.exec())
