from pathlib import Path

AUTHORS: str = "Authors: Marcin Bajkowski 193696, Stanisław Lemański 193333"

PROGRAM_NAME: str = "PAdES v1.0.0"

RSA_KEY_LENGTH: int = 4096
BLOCK_SIZE: int = 16

DEFAULT_WINDOW_SIZE: tuple[int, int] = (800, 600)
LARGE_WINDOW_SIZE: tuple[int, int] = (1200, 800)

DEFAULT_STYLESHEET_PATH = Path(__file__).resolve().parents[4] / "src/app/frontend/styles.qss"

MAIN_WINDOW_LABEL: str = "BSK Project: PAdES Qualified Electronic Signature"
GENERATOR_WINDOW_LABEL: str = "Generate RSA Keys (Public and Private)"
SECURITY_WINDOW_LABEL: str = "Sign and Verify PDF Document"

DEFAULT_MESSAGE: str = ("❌No flash drive connected!\nPlease connect one and try again...\nTo press the button again:\n\t1. Move the cursor away from the "
                        "button,\n\t2. Hover over the button again.")

BUTTONS: list = ["keygen_button", "security_button", "generate_button", "encrypt_key_button", "decrypt_key_button", "select_pdf_button", "sign_button",
                 "select_pdf_verify_button", "verify_button"]

BUTTON_STATES: dict[str, dict[str, bool]] = {
    "-encrypted-private-key": {
        "encrypt_key_button": False,
        "decrypt_key_button": True,
        "select_pdf_button": False,
        "sign_button": False,
        "select_pdf_verify_button": False,
        "verify_button": False,
    },
    "-private-key": {
        "encrypt_key_button": True,
        "decrypt_key_button": False,
        "select_pdf_button": True,
        "sign_button": True,
        "select_pdf_verify_button": False,
        "verify_button": False,
    },
    "-public-key": {
        "encrypt_key_button": False,
        "decrypt_key_button": False,
        "select_pdf_button": False,
        "sign_button": False,
        "select_pdf_verify_button": True,
        "verify_button": True,
    },
    "connected": {
        "keygen_button": True,
        "security_button": True,
        "generate_button": True,
        "encrypt_key_button": False,
        "decrypt_key_button": False,
        "select_pdf_button": False,
        "sign_button": False,
        "select_pdf_verify_button": False,
        "verify_button": False,
    },
    "default": {
        "keygen_button": False,
        "security_button": False,
        "generate_button": False,
        "encrypt_key_button": False,
        "decrypt_key_button": False,
        "select_pdf_button": False,
        "sign_button": False,
        "select_pdf_verify_button": False,
        "verify_button": False,
    }
}

UNWANTED_FILES: set[str] = {
        "._SoCS-private-key.pem",
        "._SoCS-public-key.pem",
        "._SoCS-encrypted-private-key.pem",
}

PRIVATE_KEY_FILES: set[str] = {
    "SoCS-private-key.pem",
    "SoCS-encrypted-private-key.pem",
}

PUBLIC_KEY_FILES: set[str] = {
    "SoCS-public-key.pem",
}
