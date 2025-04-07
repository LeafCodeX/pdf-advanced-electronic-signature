# pdf-advanced-electronic-signature
Security of Computer Systems | Gdańsk University of Technology 2025

## 📄 Overview
This project implements an advanced electronic signature system for PDF documents, following the PAdES (PDF Advanced Electronic Signatures) standard. It allows users to generate RSA keys, sign PDF documents and verify signatures.

- **RSA Key Generation**: Generate RSA public and private keys,
- **Flash Drive Integration**: Store and manage keys on USB flash drives,
- **Key Encryption and Decryption**: Encrypt private keys and decrypt encrypted private keys,
- **PDF Signing**: Sign PDF documents with a private key,
- **Signature Verification**: Verify the authenticity of signed PDF documents using a public key.

## 🛠️ Installation
1. Clone the repository:
    ```bash
    git clone https://github.com/LeafCodeX/pdf-advanced-electronic-signature.git
    cd pdf-advanced-electronic-signature
    ```

2. Install the required packages:
    ```bash
    pip install -r requirements.txt
    ```

## 🚀 Usage
1. **Run the application**:
    ```bash
    python3 src/app/backend/main.py
   ```

## ⚙️ Configuration
Configuration settings can be found in the `src/app/backend/util/config.py` file. Key settings include:
- `RSA_KEY_LENGTH`: Length of the RSA keys (default: 4096 bits),
- The file also contains other configuration options necessary for the application’s functionality.

## 🎗 License

> [!WARNING]
> This project is distributed under a specific license with all rights reserved. By using any of the files, you agree to the terms outlined in the license. Any unauthorized use, copying, or modification of the files may result in legal consequences. Please refer to the [LICENSE file](./LICENSE) for full details.