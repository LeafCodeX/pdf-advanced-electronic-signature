import sys
from PySide6.QtWidgets import QApplication
from icecream import ic

from src.app.frontend.windows import MainWindow

if __name__ == "__main__":
    ic.configureOutput(prefix="> debug-info: ", includeContext=True)

    app = QApplication(sys.argv)

    window = MainWindow()
    window.show()

    sys.exit(app.exec())