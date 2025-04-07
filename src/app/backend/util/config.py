AUTHORS: str = "Authors: Marcin Bajkowski 193696, Stanisław Lemański 193333"

PROGRAM_NAME: str = "PAdES v1.0.0-beta"

DEFAULT_WINDOW_SIZE: tuple[int, int] = (800, 600)
LARGE_WINDOW_SIZE: tuple[int, int] = (1200, 800)

MAIN_WINDOW_LABEL: str = "BSK Project: PAdES Qualified Electronic Signature"
GENERATOR_WINDOW_LABEL: str = "Generate RSA Keys (Public and Private)"
SECURITY_WINDOW_LABEL: str = "Sign and Verify PDF Document"

DEFAULT_MESSAGE: str = ("❌No flash drive connected!\nPlease connect one and try again...\nTo press the button again:\n\t1. Move the cursor away from the "
                        "button,\n\t2. Hover over the button again.")

BUTTONS: list = ["keygen_button", "security_button", "generate_button", "encrypt_key_button", "decrypt_key_button", "select_pdf_button", "sign_button",
                 "select_pdf_verify_button", "verify_button"]

BUTTON_STATES: dict[str, dict[str, bool]] = {
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