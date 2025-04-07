from PySide6.QtWidgets import QMainWindow, QPushButton, QWidget, QVBoxLayout, QHBoxLayout, QLayout, QLabel, QTextEdit, QListWidget
from PySide6.QtCore import Qt
from src.app.backend.util import config


class BaseWindow(QMainWindow):
    def __init__(self, window_size: tuple[int, int], title: str) -> None:
        super().__init__()
        self.resize(window_size[0], window_size[1])
        self.setWindowTitle(title)

        self.window_widget = QWidget()
        self.window_layout = QVBoxLayout()

        self.window_widget.setLayout(self.window_layout)
        self.setCentralWidget(self.window_widget)

    @staticmethod
    def add_label(text: str, identification_name: str, alignment: Qt.AlignmentFlag, layout: QLayout) -> QLabel:
        label = QLabel(text)
        label.setObjectName(identification_name)
        label.setAlignment(alignment)
        layout.addWidget(label)
        return label

    @staticmethod
    def add_message_display(identification_name: str, layout: QLayout) -> QTextEdit:
        text_edit = QTextEdit()
        text_edit.setObjectName(identification_name)
        text_edit.setReadOnly(True)
        layout.addWidget(text_edit)
        return text_edit

    @staticmethod
    def add_list_widget(identification_name: str, selection_mode: QListWidget.SelectionMode, layout: QLayout, ) -> QListWidget:
        list_widget = QListWidget()
        list_widget.setObjectName(identification_name)
        list_widget.setSelectionMode(selection_mode)
        layout.addWidget(list_widget)
        return list_widget

    def add_window_button(self, name: str, identification_name: str, main_window: QMainWindow, layout: QLayout) -> QPushButton:
        button = QPushButton(name)
        button.setObjectName(identification_name)
        button.clicked.connect(self.close)
        button.installEventFilter(self)
        button.clicked.connect(main_window.show)
        layout.addWidget(button)
        return button


class MainWindow(BaseWindow):
    def __init__(self) -> None:
        super().__init__(config.DEFAULT_WINDOW_SIZE, config.PROGRAM_NAME)

        self.generator_window = GeneratorWindow(self)
        self.security_window = SecurityWindow(self)

        self.add_label(config.MAIN_WINDOW_LABEL, "title", Qt.AlignmentFlag.AlignCenter, self.window_layout)

        self.main_button_layout = QHBoxLayout()
        self.add_window_button("🔑 Key Generation", "keygen_button", self.generator_window, self.main_button_layout)
        self.add_window_button("🔒 Signing/Verifying PDFs", "security_button", self.security_window, self.main_button_layout)
        self.window_layout.addLayout(self.main_button_layout)

        self.add_message_display("message_display", self.window_layout)
        self.add_label(config.AUTHORS, "footer", Qt.AlignmentFlag.AlignCenter, self.window_layout)


class GeneratorWindow(BaseWindow):
    def __init__(self, main_window: MainWindow) -> None:
        super().__init__(config.DEFAULT_WINDOW_SIZE, config.PROGRAM_NAME)
        self.main_window = main_window

        self.add_label(config.GENERATOR_WINDOW_LABEL, "title", Qt.AlignmentFlag.AlignCenter, self.window_layout)

        self.gen_usb_list_widget = self.add_list_widget("gen_usb_list_widget", QListWidget.SelectionMode.SingleSelection, self.window_layout)
        self.generator_button_layout = QHBoxLayout()
        self.add_window_button("🔑 Generate Keys", "generate_button", self.main_window, self.generator_button_layout)
        self.add_window_button("↩ Return", "gen_return_button", self.main_window, self.generator_button_layout)
        self.window_layout.addLayout(self.generator_button_layout)

        self.message_display = self.add_message_display("message_display", self.window_layout)
        self.add_label(config.AUTHORS, "footer", Qt.AlignmentFlag.AlignCenter, self.window_layout)


class SecurityWindow(BaseWindow):
    def __init__(self, main_window: MainWindow) -> None:
        super().__init__(config.LARGE_WINDOW_SIZE, config.PROGRAM_NAME)
        self.main_window = main_window

        self.add_label(config.SECURITY_WINDOW_LABEL, "title", Qt.AlignmentFlag.AlignCenter, self.window_layout)

        self.security_layout = QHBoxLayout()
        self.security_layout_left = QVBoxLayout()
        self.sec_usb_list_widget = self.add_list_widget("sec_usb_list_widget", QListWidget.SelectionMode.SingleSelection, self.security_layout_left)
        self.security_layout_left_col = QHBoxLayout()
        self.add_window_button("🔒 Encrypt Key", "encrypt_key_button", self.main_window, self.security_layout_left_col)
        self.add_window_button("🔐 Decrypt Key", "decrypt_key_button", self.main_window, self.security_layout_left_col)
        self.security_layout_left.addLayout(self.security_layout_left_col)
        self.add_window_button("📑 Select PDF", "select_pdf_button", self.main_window, self.security_layout_left)
        self.add_window_button("✎ᝰ. Sign PDF", "sign_button", self.main_window, self.security_layout_left)
        self.security_layout.addLayout(self.security_layout_left)

        self.security_layout_right = QVBoxLayout()
        self.sec_key_list_widget = self.add_list_widget("sec_key_list_widget", QListWidget.SelectionMode.SingleSelection, self.security_layout_right)
        self.add_window_button("📑 Select PDF to Verify", "select_pdf_verify_button", self.main_window, self.security_layout_right)
        self.add_window_button("☑️ Verify PDF", "verify_button", self.main_window, self.security_layout_right)
        self.add_window_button("↩ Return", "sec_return_button", self.main_window, self.security_layout_right)
        self.security_layout.addLayout(self.security_layout_right)

        self.window_layout.addLayout(self.security_layout)
        self.message_display = self.add_message_display("message_display", self.window_layout)
        self.add_label(config.AUTHORS, "footer", Qt.AlignmentFlag.AlignCenter, self.window_layout)
