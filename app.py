from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import base64
import hashlib
from Crypto.Cipher import AES, DES3, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad

app = Flask(__name__)
CORS(app)

# Generate RSA key pair
RSA_KEY = RSA.generate(2048)


class EncryptionToolkit:
    @staticmethod
    def generate_key(key_input, length=16):
        """Generate a consistent key from input string."""
        # Use SHA-256 to create a consistent key
        return hashlib.sha256(key_input.encode()).digest()[:length]

    @staticmethod
    def aes_encrypt(text, key):
        """AES encryption method."""
        try:
            # Generate consistent key
            key = EncryptionToolkit.generate_key(key)

            # Create cipher
            cipher = AES.new(key, AES.MODE_ECB)

            # Encrypt and encode
            encrypted = cipher.encrypt(pad(text.encode(), AES.block_size))
            return base64.b64encode(encrypted).decode()
        except Exception as e:
            return f"AES Encryption Error: {str(e)}"

    @staticmethod
    def aes_decrypt(encrypted_text, key):
        """AES decryption method."""
        try:
            # Generate consistent key
            key = EncryptionToolkit.generate_key(key)

            # Create cipher
            cipher = AES.new(key, AES.MODE_ECB)

            # Decrypt
            decrypted = unpad(cipher.decrypt(base64.b64decode(encrypted_text)), AES.block_size)
            return decrypted.decode()
        except Exception as e:
            return f"AES Decryption Error: {str(e)}"

    @staticmethod
    def des_encrypt(text, key):
        """DES encryption method."""
        try:
            # Generate consistent key
            key = EncryptionToolkit.generate_key(key, length=16)

            # Create cipher
            cipher = DES3.new(key, DES3.MODE_ECB)

            # Encrypt and encode
            encrypted = cipher.encrypt(pad(text.encode(), DES3.block_size))
            return base64.b64encode(encrypted).decode()
        except Exception as e:
            return f"DES Encryption Error: {str(e)}"

    @staticmethod
    def des_decrypt(encrypted_text, key):
        """DES decryption method."""
        try:
            # Generate consistent key
            key = EncryptionToolkit.generate_key(key, length=16)

            # Create cipher
            cipher = DES3.new(key, DES3.MODE_ECB)

            # Decrypt
            decrypted = unpad(cipher.decrypt(base64.b64decode(encrypted_text)), DES3.block_size)
            return decrypted.decode()
        except Exception as e:
            return f"DES Decryption Error: {str(e)}"

    @staticmethod
    def rsa_encrypt(text):
        """RSA encryption method."""
        try:
            # Use public key for encryption
            cipher_rsa = PKCS1_OAEP.new(RSA_KEY.publickey())
            encrypted = cipher_rsa.encrypt(text.encode())
            return base64.b64encode(encrypted).decode()
        except Exception as e:
            return f"RSA Encryption Error: {str(e)}"

    @staticmethod
    def rsa_decrypt(encrypted_text):
        """RSA decryption method."""
        try:
            # Use private key for decryption
            cipher_rsa = PKCS1_OAEP.new(RSA_KEY)
            decrypted = cipher_rsa.decrypt(base64.b64decode(encrypted_text))
            return decrypted.decode()
        except Exception as e:
            return f"RSA Decryption Error: {str(e)}"


@app.route('/')
def index():
    """Render the main page."""
    return render_template('index.html')


@app.route('/encrypt', methods=['POST'])
def encrypt():
    """Handle encryption requests."""
    data = request.json
    encryption_type = data.get('type')
    text = data.get('text', '')
    key = data.get('key', '')

    # Select encryption method based on type
    if encryption_type == 'aes':
        result = EncryptionToolkit.aes_encrypt(text, key)
    elif encryption_type == 'des':
        result = EncryptionToolkit.des_encrypt(text, key)
    elif encryption_type == 'rsa':
        result = EncryptionToolkit.rsa_encrypt(text)
    else:
        return jsonify({'error': 'Invalid encryption type'}), 400

    return jsonify({'encrypted': result})


@app.route('/decrypt', methods=['POST'])
def decrypt():
    """Handle decryption requests."""
    data = request.json
    encryption_type = data.get('type')
    encrypted_text = data.get('text', '')
    key = data.get('key', '')

    # Select decryption method based on type
    try:
        if encryption_type == 'aes':
            result = EncryptionToolkit.aes_decrypt(encrypted_text, key)
        elif encryption_type == 'des':
            result = EncryptionToolkit.des_decrypt(encrypted_text, key)
        elif encryption_type == 'rsa':
            result = EncryptionToolkit.rsa_decrypt(encrypted_text)
        else:
            return jsonify({'error': 'Invalid encryption type'}), 400

        return jsonify({'decrypted': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True)