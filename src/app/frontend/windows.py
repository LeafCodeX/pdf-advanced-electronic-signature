from PySide6.QtWidgets import (QMainWindow, QPushButton, QWidget, QVBoxLayout, QHBoxLayout, QLayout, QLabel, QTextEdit, QListWidget, QListWidgetItem,
                               QInputDialog, QLineEdit, QFileDialog)
from PySide6.QtCore import Qt, QEvent
from src.app.backend.util import config, util, keygen, security
from typing import Optional
from icecream import ic
import os


class BaseWindow(QMainWindow):
    """
    @class BaseWindow
    @brief Base class for creating application windows with common layout and styling functionalities.
    """
    def __init__(self, window_size: tuple[int, int], title: str, stylesheet_path: str) -> None:
        """
        @brief Initializes the base window with a specific size, title, and stylesheet.

        @param window_size Tuple specifying the width and height of the window.
        @param title Title of the window.
        @param stylesheet_path Path to the stylesheet file used for window styling.
        """
        super().__init__()
        self.resize(window_size[0], window_size[1])
        self.setWindowTitle(title)
        self.stylesheet_path = stylesheet_path

        self.window_widget = QWidget()
        self.window_layout = QVBoxLayout()

        self.window_widget.setLayout(self.window_layout)
        self.setCentralWidget(self.window_widget)
        self.load_stylesheet(self.stylesheet_path)


    @staticmethod
    def add_label(text: str, identification_name: str, alignment: Qt.AlignmentFlag, layout: QLayout) -> QLabel:
        """
        @brief Adds a label to the given layout.

        @param text Text to display on the label.
        @param identification_name Object name used for identifying the label widget.
        @param alignment Text alignment inside the label.
        @param layout Layout where the label will be added.
        @return QLabel Created QLabel widget.
        """
        label = QLabel(text)
        label.setObjectName(identification_name)
        label.setAlignment(alignment)
        layout.addWidget(label)
        return label

    @staticmethod
    def add_message_display(identification_name: str, layout: QLayout) -> QTextEdit:
        """
        @brief Adds a read-only text display widget to the given layout.

        @param identification_name Object name used for identifying the text edit widget.
        @param layout Layout where the text edit widget will be added.
        @return QTextEdit Created QTextEdit widget.
        """
        text_edit = QTextEdit()
        text_edit.setObjectName(identification_name)
        text_edit.setReadOnly(True)
        layout.addWidget(text_edit)
        return text_edit

    @staticmethod
    def add_list_widget(identification_name: str, selection_mode: QListWidget.SelectionMode, layout: QLayout, ) -> QListWidget:
        """
        @brief Adds a list widget to the given layout.

        @param identification_name Object name used for identifying the list widget.
        @param selection_mode Selection mode that defines how items can be selected (e.g., single or multiple).
        @param layout Layout where the list widget will be added.
        @return QListWidget Created QListWidget widget.
        """
        list_widget = QListWidget()
        list_widget.setObjectName(identification_name)
        list_widget.setSelectionMode(selection_mode)
        layout.addWidget(list_widget)
        return list_widget

    def add_function_button(self, name: str, identification_name: str, function: callable, layout: QLayout) -> QPushButton:
        """
        @brief Adds a function button to the given layout and connects it to the specified function.

        @param name Text to be displayed on the button.
        @param identification_name Object name used for identifying the button widget.
        @param function Function to be called when the button is clicked.
        @param layout Layout where the button will be added.
        @return QPushButton Created QPushButton widget.
        """
        button = QPushButton(name)
        button.setObjectName(identification_name)
        button.clicked.connect(function)
        button.installEventFilter(self)
        layout.addWidget(button)
        return button

    def add_window_button(self, name: str, identification_name: str, main_window: QMainWindow, layout: QLayout) -> QPushButton:
        """
        @brief Adds a button that closes the current window and opens the specified main window.

        @param name Text to be displayed on the button.
        @param identification_name Object name used for identifying the button widget.
        @param main_window Window to be shown after closing the current window.
        @param layout Layout where the button will be added.
        @return QPushButton Created QPushButton widget.
        """
        button = QPushButton(name)
        button.setObjectName(identification_name)
        button.clicked.connect(self.close)
        button.installEventFilter(self)
        button.clicked.connect(main_window.show)
        layout.addWidget(button)
        return button

    def update_button_states(self, state: str) -> None:
        """
        @brief Updates the enabled/disabled states of buttons based on the given application state.

        @param state Key used to retrieve the corresponding button states from the configuration.
        """
        button_states: dict[str, bool] = config.BUTTON_STATES.get(state, config.BUTTON_STATES["default"])
        for button_name, enabled in button_states.items():
            button = self.findChild(QPushButton, button_name)
            if button:
                button.setEnabled(enabled)

    def load_stylesheet(self, stylesheet_path: str) -> None:
        """
        @brief Loads and applies a stylesheet from a specified file path.

        @param stylesheet_path Path to the stylesheet file.
        """
        try:
            with open(stylesheet_path, "r") as file:
                self.setStyleSheet(file.read())
        except Exception as ex:
            ic(f"{ex}")


class MainWindow(BaseWindow):
    """
    @class MainWindow
    @brief Main application window that allows the user to navigate to key generation or document signing/verification functionalities.
    """
    def __init__(self) -> None:
        """
        @brief Initializes the main window, setting up buttons and navigation to key generation and signing functionalities.
        """
        super().__init__(config.DEFAULT_WINDOW_SIZE, config.PROGRAM_NAME, config.DEFAULT_STYLESHEET_PATH)
        self.flash_drives: list[dict[str, str]] = []

        self.generator_window = GeneratorWindow(self, self.flash_drives)
        self.security_window = SecurityWindow(self, self.flash_drives)

        self.add_label(config.MAIN_WINDOW_LABEL, "title", Qt.AlignmentFlag.AlignCenter, self.window_layout)

        self.main_button_layout = QHBoxLayout()
        self.add_window_button("🔑 Key Generation", "keygen_button", self.generator_window, self.main_button_layout)
        self.add_window_button("🔒 Signing/Verifying PDFs", "security_button", self.security_window, self.main_button_layout)
        self.window_layout.addLayout(self.main_button_layout)

        self.add_message_display("message_display", self.window_layout)
        self.add_label(config.AUTHORS, "footer", Qt.AlignmentFlag.AlignCenter, self.window_layout)

    def eventFilter(self, obj, event) -> bool:
        """
        @brief Handles button hover and click events, updating connected flash drives information and button states.

        @param obj The object generating the event.
        @param event The event being processed.
        @return bool True if the event is fully handled, otherwise passes the event to the base class.
        """
        message_display = self.findChild(QTextEdit, "message_display")
        if event.type() == QEvent.Type.Enter and obj.objectName() in config.BUTTONS:
            self.flash_drives = util.get_flash_drive_info()
            if self.flash_drives:
                message_display.setText("✅ Connected flash drives:")
                flash_drive_info: str = "\n".join([f"Device: {drive['deviceName']}\n\tPath: {drive['devicePath']}\n" for drive in self.flash_drives])
                message_display.append(flash_drive_info)
                self.update_button_states("connected")
            else:
                message_display.setText(config.DEFAULT_MESSAGE)
                self.update_button_states("default")
        elif event.type() == QEvent.Type.Leave and obj.objectName() in config.BUTTONS:
            message_display.clear()
        elif event.type() == QEvent.Type.MouseButtonPress and obj.objectName() in config.BUTTONS:
            self.flash_drives = util.get_flash_drive_info()
            if not self.flash_drives:
                self.update_button_states("default")
                message_display.setText(config.DEFAULT_MESSAGE)
                return True
        return super().eventFilter(obj, event)


class GeneratorWindow(BaseWindow):
    """
    @class GeneratorWindow
    @brief Window responsible for generating RSA key pairs and saving them to a selected flash drive.
    """
    def __init__(self, main_window: MainWindow, flash_drives: list[dict[str, str]]) -> None:
        """
        @brief Initializes the Generator Window, setting up the UI components and connecting events.

        @param main_window Reference to the main application window for navigation purposes.
        @param flash_drives List of detected flash drives available for key generation.
        """
        super().__init__(config.DEFAULT_WINDOW_SIZE, config.PROGRAM_NAME, config.DEFAULT_STYLESHEET_PATH)
        self.main_window = main_window
        self.flash_drives: list[dict[str, str]] = flash_drives
        self.previous_flash_drives: list[dict[str, str]] = []
        self.selected_drive: Optional[dict[str, str]] = None

        self.add_label(config.GENERATOR_WINDOW_LABEL, "title", Qt.AlignmentFlag.AlignCenter, self.window_layout)

        self.gen_usb_list_widget = self.add_list_widget("gen_usb_list_widget", QListWidget.SelectionMode.SingleSelection, self.window_layout)
        self.gen_usb_list_widget.itemSelectionChanged.connect(self.on_usb_selection_changed)
        self.generator_button_layout = QHBoxLayout()
        self.add_function_button("🔑 Generate Keys", "generate_button", self.generate_and_save_keys, self.generator_button_layout)
        self.add_window_button("↩ Return", "gen_return_button", self.main_window, self.generator_button_layout)
        self.window_layout.addLayout(self.generator_button_layout)

        self.message_display = self.add_message_display("message_display", self.window_layout)
        self.add_label(config.AUTHORS, "footer", Qt.AlignmentFlag.AlignCenter, self.window_layout)

    def update_usb_list(self) -> None:
        """
        @brief Updates the list widget displaying available flash drives, showing information about existing keys.
        """
        current_flash_drives = util.get_flash_drive_info()
        new_flash_drive_info = []

        for drive in current_flash_drives:
            device_path = drive["devicePath"]
            private_key_count, public_key_count, _, _ = keygen.count_keys(device_path)
            new_flash_drive_info.append({"devicePath": device_path, "deviceName": drive["deviceName"], "private_key_count": private_key_count,
                                         "public_key_count": public_key_count})

        key_state_changed = (len(new_flash_drive_info) != len(self.previous_flash_drives) or any(new != old for new, old in zip(new_flash_drive_info,
                                                                                                                                self.previous_flash_drives)))
        if not key_state_changed:
            return

        self.previous_flash_drives = new_flash_drive_info
        self.gen_usb_list_widget.clear()

        placeholder_item = QListWidgetItem("Select a flash drive:")
        placeholder_item.setFlags(Qt.ItemFlag.NoItemFlags)
        self.gen_usb_list_widget.addItem(placeholder_item)

        for drive in new_flash_drive_info:
            item_text = f'{drive["deviceName"]} - {drive["devicePath"]}     (Keys: {drive["private_key_count"]} private, {drive["public_key_count"]} public)'
            list_item = QListWidgetItem(item_text)
            list_item.setData(Qt.ItemDataRole.UserRole, drive)
            if self.selected_drive and self.selected_drive["devicePath"] == drive["devicePath"]:
                list_item.setSelected(True)
            self.gen_usb_list_widget.addItem(list_item)

    def showEvent(self, event) -> None:
        """
        @brief Updates the flash drive list when the window becomes visible.

        @param event Show event triggered when the window is shown.
        """
        self.update_usb_list()
        super().showEvent(event)

    def eventFilter(self, obj, event) -> bool:
        """
        @brief Handles button hover events to refresh flash drive list and update button states.

        @param obj The object generating the event.
        @param event The event being processed.
        @return bool True if the event is fully handled, otherwise passes the event to the base class.
        """
        message_display = self.findChild(QTextEdit, "message_display")
        if event.type() == QEvent.Type.Enter and obj.objectName() in config.BUTTONS:
            self.flash_drives = util.get_flash_drive_info()
            if self.flash_drives:
                self.update_usb_list()
                self.update_button_states("connected")
            else:
                self.update_usb_list()
                message_display.setText(config.DEFAULT_MESSAGE)
                self.update_button_states("default")
        elif event.type() == QEvent.Type.Leave and obj.objectName() in config.BUTTONS:
            message_display.clear()
            self.update_usb_list()
        return super().eventFilter(obj, event)

    def closeEvent(self, event) -> None:
        """
        @brief Resets the selection and updates the main window flash drive state when the Generator Window is closed.

        @param event Close event triggered when the window is closed.
        """
        self.gen_usb_list_widget.clearSelection()
        self.flash_drives = util.get_flash_drive_info()
        self.main_window.flash_drives = self.flash_drives
        self.main_window.update_button_states("connected" if self.flash_drives else "default")
        message_display = self.main_window.findChild(QTextEdit, "message_display")
        if not self.flash_drives:
            message_display.setText(config.DEFAULT_MESSAGE)
        else:
            message_display.clear()
        self.message_display.clear()
        self.selected_drive = None
        super().closeEvent(event)

    def on_usb_selection_changed(self) -> None:
        """
        @brief Handles the event when a different flash drive is selected from the list, updating the selected drive.
        """
        selected_item = self.gen_usb_list_widget.currentItem()
        if selected_item and selected_item.data(Qt.ItemDataRole.UserRole):
            self.selected_drive = selected_item.data(Qt.ItemDataRole.UserRole)

    def generate_and_save_keys(self) -> None:
        """
        @brief Generates a new RSA key pair and saves the private and public keys to the selected flash drive.
        """
        message_display = self.findChild(QTextEdit, "message_display")
        if not self.selected_drive:
            message_display.setText("❌ Please select a flash drive from the list!")
            return
        flash_drive_info = self.selected_drive
        device_path = flash_drive_info["devicePath"]
        device_name = flash_drive_info["deviceName"]
        message_display.append(f"✅ Generating RSA keys with a length of {config.RSA_KEY_LENGTH} bits for {device_name}...")
        private_key_path, public_key_path = keygen.generate_and_save_keys(device_path)
        if private_key_path and public_key_path:
            message_display.append(f"{private_key_path}\n{public_key_path}\n✅ Generating and saving keys completed successfully!")
        else:
            message_display.setText(f"{config.DEFAULT_MESSAGE}\n❌ Error generating and saving keys!")


class SecurityWindow(BaseWindow):
    """
    @class SecurityWindow
    @brief Window responsible for encrypting, decrypting, signing, and verifying PDF files using RSA keys stored on a flash drive.
    """
    def __init__(self, main_window: MainWindow, flash_drives: list[dict[str, str]]) -> None:
        """
        @brief Initializes the Security Window, setting up the UI components for encryption, decryption, signing, and verifying operations.

        @param main_window Reference to the main application window for navigation purposes.
        @param flash_drives List of detected flash drives available for cryptographic operations.
        """
        super().__init__(config.LARGE_WINDOW_SIZE, config.PROGRAM_NAME, config.DEFAULT_STYLESHEET_PATH)
        self.main_window = main_window
        self.flash_drives: list[dict[str, str]] = flash_drives
        self.previous_flash_drives: list[dict[str, str]] = []
        self.selected_drive: Optional[dict[str, str]] = None
        self.selected_key: Optional[str] = None
        self.selected_pdf_path_to_sign: Optional[str] = None
        self.selected_pdf_path_to_verify: Optional[str] = None

        self.add_label(config.SECURITY_WINDOW_LABEL, "title", Qt.AlignmentFlag.AlignCenter, self.window_layout)

        self.security_layout = QHBoxLayout()
        self.security_layout_left = QVBoxLayout()
        self.sec_usb_list_widget = self.add_list_widget("sec_usb_list_widget", QListWidget.SelectionMode.SingleSelection, self.security_layout_left)
        self.sec_usb_list_widget.itemSelectionChanged.connect(self.on_usb_selection_changed)
        self.security_layout_left_col = QHBoxLayout()
        self.add_function_button("🔒 Encrypt Key", "encrypt_key_button", self.handle_encrypt_and_decrypt_private_key, self.security_layout_left_col)
        self.add_function_button("🔐 Decrypt Key", "decrypt_key_button", self.handle_encrypt_and_decrypt_private_key, self.security_layout_left_col)
        self.security_layout_left.addLayout(self.security_layout_left_col)
        self.add_function_button("📑 Select PDF", "select_pdf_button", self.select_pdf_to_sign, self.security_layout_left)
        self.add_function_button("✎ᝰ. Sign PDF", "sign_button", self.sign_selected_pdf, self.security_layout_left)
        self.security_layout.addLayout(self.security_layout_left)

        self.security_layout_right = QVBoxLayout()
        self.sec_key_list_widget = self.add_list_widget("sec_key_list_widget", QListWidget.SelectionMode.SingleSelection, self.security_layout_right)
        self.sec_key_list_widget.itemSelectionChanged.connect(self.on_key_selection_changed)
        self.add_function_button("📑 Select PDF to Verify", "select_pdf_verify_button", self.select_pdf_to_verify, self.security_layout_right)
        self.add_function_button("☑️ Verify PDF", "verify_button", self.verify_selected_pdf, self.security_layout_right)
        self.add_window_button("↩ Return", "sec_return_button", self.main_window, self.security_layout_right)
        self.security_layout.addLayout(self.security_layout_right)

        self.window_layout.addLayout(self.security_layout)
        self.message_display = self.add_message_display("message_display", self.window_layout)
        self.add_label(config.AUTHORS, "footer", Qt.AlignmentFlag.AlignCenter, self.window_layout)

    def update_usb_list(self) -> None:
        """
        @brief Updates the list of connected flash drives and their available RSA keys.
        """
        current_flash_drives = util.get_flash_drive_info()
        new_flash_drive_info = []

        for drive in current_flash_drives:
            device_path = drive["devicePath"]
            private_key_count, public_key_count, _, _ = keygen.count_keys(device_path)
            new_flash_drive_info.append({"devicePath": device_path, "deviceName": drive["deviceName"], "private_key_count": private_key_count,
                                         "public_key_count": public_key_count})

        key_state_changed = (len(new_flash_drive_info) != len(self.previous_flash_drives) or any(new != old for new, old in zip(new_flash_drive_info,
                                                                                                                                self.previous_flash_drives)))

        if not key_state_changed:
            return

        self.previous_flash_drives = new_flash_drive_info
        self.sec_usb_list_widget.clear()

        placeholder_item = QListWidgetItem("Select a flash drive:")
        placeholder_item.setFlags(Qt.ItemFlag.NoItemFlags)
        self.sec_usb_list_widget.addItem(placeholder_item)

        for drive in new_flash_drive_info:
            item_text = f'{drive["deviceName"]} - {drive["devicePath"]}'
            list_item = QListWidgetItem(item_text)
            list_item.setData(Qt.ItemDataRole.UserRole, drive)
            if self.selected_drive and self.selected_drive["devicePath"] == drive["devicePath"]:
                list_item.setSelected(True)
            self.sec_usb_list_widget.addItem(list_item)

    def showEvent(self, event) -> None:
        """
        @brief Handles window show events by refreshing the flash drive and key lists.

        @param event Event triggered when the window is shown.
        """
        self.flash_drives = util.get_flash_drive_info()
        self.update_button_states("connected" if self.flash_drives else "default")
        self.update_usb_list()
        placeholder_item = QListWidgetItem("Select a key for next operations:")
        placeholder_item.setFlags(Qt.ItemFlag.NoItemFlags)
        self.sec_key_list_widget.addItem(placeholder_item)
        super().showEvent(event)

    def eventFilter(self, obj, event) -> bool:
        """
        @brief Handles button hover events, updating flash drive lists and button states based on connection status.

        @param obj The object generating the event.
        @param event The event being processed.
        @return bool True if the event is fully handled, otherwise passes the event to the base class.
        """
        message_display = self.findChild(QTextEdit, "message_display")
        if event.type() == QEvent.Type.Enter and obj.objectName() in config.BUTTONS:
            self.flash_drives = util.get_flash_drive_info()
            if self.flash_drives:
                self.update_usb_list()
            else:
                self.update_usb_list()
                message_display.setText(config.DEFAULT_MESSAGE)
                self.update_button_states("default")
        elif event.type() == QEvent.Type.Leave and obj.objectName() in config.BUTTONS:
            message_display.clear()
            self.update_usb_list()
        return super().eventFilter(obj, event)

    def closeEvent(self, event) -> None:
        """
        @brief Handles window closing events, clearing selections and resetting the main window state.

        @param event Event triggered when the window is closed.
        """
        self.sec_usb_list_widget.clearSelection()
        self.flash_drives = util.get_flash_drive_info()
        self.main_window.flash_drives = self.flash_drives
        self.main_window.update_button_states("connected" if self.flash_drives else "default")
        message_display = self.main_window.findChild(QTextEdit, "message_display")
        if not self.flash_drives:
            message_display.setText(config.DEFAULT_MESSAGE)
        else:
            message_display.clear()
        self.message_display.clear()
        self.sec_key_list_widget.clear()
        self.selected_drive = None
        self.selected_key = None
        self.selected_pdf_path_to_sign = None
        self.selected_pdf_path_to_verify = None
        super().closeEvent(event)

    def on_usb_selection_changed(self) -> None:
        """
        @brief Updates the selected flash drive when a different device is selected from the list.
        """
        selected_item = self.sec_usb_list_widget.currentItem()
        if selected_item and selected_item.data(Qt.ItemDataRole.UserRole):
            self.selected_drive = selected_item.data(Qt.ItemDataRole.UserRole)
            self.load_keys(self.selected_drive["devicePath"] if self.selected_drive else "")

    def load_keys(self, device_path: str) -> None:
        """
        @brief Loads RSA keys from the selected flash drive and displays them in the key list widget.

        @param device_path Path to the selected flash drive.
        """
        message_display = self.findChild(QTextEdit, "message_display")
        self.sec_key_list_widget.clear()

        placeholder_item = QListWidgetItem("Select a key for next operations:")
        placeholder_item.setFlags(Qt.ItemFlag.NoItemFlags)
        self.sec_key_list_widget.addItem(placeholder_item)

        if not self.selected_drive:
            return

        private_key_count, public_key_count, private_key_paths, public_key_paths = keygen.count_keys(device_path)

        if private_key_count == 0 and public_key_count == 0:
            message_display.setText("❌ No keys found on the selected flash drive!")
            return

        for key_type, key_paths in [("Private Key", private_key_paths), ("Public Key", public_key_paths)]:
            for path in key_paths:
                parent_folder = os.path.basename(os.path.dirname(path))
                item = QListWidgetItem(f"../{parent_folder}/{os.path.basename(path)}")
                item.setData(Qt.ItemDataRole.UserRole, path)
                self.sec_key_list_widget.addItem(item)

    def on_key_selection_changed(self) -> None:
        """
        @brief Updates the selected key when a different key is selected from the key list.
        """
        selected_item = self.sec_key_list_widget.currentItem()
        if selected_item and selected_item.data(Qt.ItemDataRole.UserRole):
            self.selected_key = selected_item.data(Qt.ItemDataRole.UserRole)
            key_name = os.path.basename(self.selected_key)
            if key_name in config.PRIVATE_KEY_FILES:
                if "encrypted" in key_name:
                    self.update_button_states("-encrypted-private-key")
                else:
                    self.update_button_states("-private-key")
            elif key_name in config.PUBLIC_KEY_FILES:
                self.update_button_states("-public-key")

    def handle_encrypt_and_decrypt_private_key(self):
        """
        @brief Encrypts or decrypts the selected private RSA key based on the user's PIN input and action selected.
        """
        sender = self.sender()
        action = "encrypt" if sender.objectName() == "encrypt_key_button" else "decrypt"

        pin, input_window = QInputDialog.getText(self, config.PROGRAM_NAME, "Enter code (PIN):", QLineEdit.EchoMode.Password)

        if input_window and pin:
            if not (pin.isdigit() and len(pin) == 4):
                self.message_display.setText("❌ PIN must consist of exactly 4 digits!")
                return
            selected_items = self.sec_key_list_widget.selectedItems()
            if selected_items:
                selected_key_path = selected_items[0].data(Qt.ItemDataRole.UserRole)
                if action == "encrypt":
                    encrypted_key_path = security.encrypt_private_key(selected_key_path, pin)
                    if encrypted_key_path:
                        self.message_display.setText(f"✅ Private key encrypted successfully! Encrypted key path:\n{encrypted_key_path}")
                    else:
                        self.message_display.setText("❌ Failed to encrypt private key!")
                else:
                    decrypted_key_path = security.decrypt_private_key(selected_key_path, pin)
                    if decrypted_key_path:
                        self.message_display.setText(f"✅ Private key decrypted successfully! Decrypted key path:\n{decrypted_key_path}")
                    else:
                        self.message_display.setText("❌ Failed to decrypt private key!\nPlease check the PIN and try again...")
                self.load_keys(self.selected_drive["devicePath"])
                self.update_button_states("connected")
            else:
                self.message_display.setText("❌ No key selected for encryption/decryption!\nPlease select a key from the list and try again...")
        else:
            self.message_display.setText("❌ Failed encrypting/decrypting the key!\nPlease enter a PIN and try again...")

    def select_pdf_to_sign(self) -> None:
        """
        @brief Opens a file dialog to select a PDF file for signing.
        """
        pdf_path, _ = QFileDialog.getOpenFileName(self, "Select PDF to Sign", "", "PDF Files (*.pdf)")
        if pdf_path:
            self.selected_pdf_path_to_sign = pdf_path
            self.message_display.setText(f"✅ PDF selected for signing:\n{pdf_path}")
        else:
            self.message_display.setText("❌ No PDF selected for signing!\nPlease select a PDF file and try again...")

    def select_pdf_to_verify(self) -> None:
        """
        @brief Signs the selected PDF file using the selected private key and an optional signer name.
        """
        pdf_path, _ = QFileDialog.getOpenFileName(self, "Select PDF to Verify", "", "PDF Files (*.pdf)")
        if pdf_path:
            self.selected_pdf_path_to_verify = pdf_path
            self.message_display.setText(f"✅ PDF selected for verification:\n{pdf_path}")
        else:
            self.message_display.setText("❌ No PDF selected for verification!\nPlease select a PDF file and try again...")

    def sign_selected_pdf(self) -> None:
        """
        @brief Signs the selected PDF file using the selected private key and an optional signer name.
        """
        if not self.selected_pdf_path_to_sign:
            self.message_display.setText("❌ No PDF selected for signing!\nPlease select a PDF file and try again...")
            return
        if not self.selected_key or not self.selected_key.endswith("SoCS-private-key.pem"):
            self.message_display.setText("❌ No private key selected for signing!\nPlease select a private key and try again...")
            return
        name, input_name = QInputDialog.getText(self, config.PROGRAM_NAME, "Signed by:")
        if not input_name or not name:
            name = " "
        signed_pdf_path = security.sign_pdf(self.selected_pdf_path_to_sign, self.selected_key, name)
        if signed_pdf_path and os.path.isfile(signed_pdf_path):
            if name.strip():
                self.message_display.setText(f"✅ PDF signed successfully by {name}! \nSigned PDF path: {signed_pdf_path}")
            else:
                self.message_display.setText(f"✅ PDF signed successfully! \nSigned PDF path: {signed_pdf_path}")
        else:
            self.message_display.setText("❌ PDF signing failed! Please check the inputs and try again.")

    def verify_selected_pdf(self) -> None:
        """
        @brief Verifies the signature of the selected PDF file using the selected public key.

        Displays signer information and signature validation result.
        """
        if not self.selected_pdf_path_to_verify:
            self.message_display.setText("❌ No PDF selected for verification!\nPlease select a PDF file and try again...")
            return

        if not self.selected_key or not self.selected_key.endswith("SoCS-public-key.pem"):
            self.message_display.setText("❌ No public key selected for verification!\nPlease select a public key and try again...")
            return

        result = security.verify_pdf(self.selected_pdf_path_to_verify, self.selected_key)

        if isinstance(result, tuple) and len(result) == 5:
            is_valid, signer, signature_date, signature_length, key_size = result
            if is_valid:
                self.message_display.setText(f"✅ PDF verification successful!\nPDF path: {self.selected_pdf_path_to_verify}\n\nSigner: {signer}\n"
                                             f"Signature date: {signature_date}\nSignature length: {signature_length} bytes and key size: {key_size} bits!")
            else:
                self.message_display.setText(f"❌ PDF verification failed!\nCheck the inputs and try again...\nPDF path: {self.selected_pdf_path_to_verify}")
        else:
            self.message_display.setText("❌ Unexpected result from verification function! Check the inputs and try again...")
