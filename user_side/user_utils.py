import json
import socket

from cryptography.hazmat.primitives.asymmetric.ec import  EllipticCurvePublicKey, EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

SERVER_IP = "127.0.0.1"  # Server IP
SERVER_PORT = 5000  # Server port

def load_private_key(private_key_file: str):
    """
    Load a private key from a PEM file.

    Args:
        private_key_file (str): Path to the private key PEM file.

    Returns:
        EllipticCurvePrivateKey: The deserialized private key.
    """
    with open(private_key_file, "rb") as file:
        private_key = serialization.load_pem_private_key(
            file.read(),
            password=None,  # Use a password if the private key is encrypted
            backend=default_backend()
        )
    return private_key

def load_public_key(public_key_file: str):
    """
    Load a public key from a PEM file.

    Args:
        public_key_file (str): Path to the public key PEM file.

    Returns:
        EllipticCurvePublicKey: The deserialized public key.
    """
    with open(public_key_file, "rb") as file:
        public_key = serialization.load_pem_public_key(
            file.read(),
            backend=default_backend()
        )
    return public_key


def aes_decrypt(encrypted_data: dict) -> bytes:
    """
    Decrypts the data encrypted by aes_encrypt.

    Args:
        encrypted_data (dict): Dictionary containing the key, iv, and ciphertext.

    Returns:
        bytes: The original plaintext data.
    """
    key = encrypted_data["key"]
    iv = encrypted_data["iv"]
    ciphertext = encrypted_data["ciphertext"]

    # Create a Cipher object using the key and IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    # Decrypt the ciphertext
    padded_message = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove the PKCS7 padding
    unpad = padding.PKCS7(128).unpadder()
    plaintext = unpad.update(padded_message) + unpad.finalize()

    return plaintext


def create_shared_secret(private_key: ec.EllipticCurvePrivateKey, peer_public_key: ec.EllipticCurvePublicKey) -> bytes:
    """
    Generate a shared secret using ECDH (Elliptic Curve Diffie-Hellman).

    Args:
        private_key (EllipticCurvePrivateKey): The user's private key.
        peer_public_key (EllipticCurvePublicKey): The peer's public key.

    Returns:
        bytes: The derived shared secret.
    """
    # Generate the shared secret
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    return shared_secret

#"""

def send_json(ip, port, data):
    """
    Sends JSON data to a specified IP and port.

    Args:
        ip (str): The IP address to send data to.
        port (int): The port number to send data to.
        data (dict): The JSON data to send.
    """
    # Convert the dictionary to a JSON string
    json_data = json.dumps(data)

    # Create a socket connection
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((ip, port))  # Connect to the server
        client_socket.sendall(json_data.encode('utf-8'))  # Send JSON data

        # Receive the server's response
        response = client_socket.recv(1024).decode('utf-8')
        print("Server response:", response)
        return response


# if __name__ == "__main__":
#     # Original plaintext data
#     original_data = b"Sensitive information to encrypt!"
#     # Call the function to generate and save keys
#     generate_ecc_keys(private_key_file="private_key.pem", public_key_file="public_key.pem")
#     # Paths to the key files
#     private_key_path = "private_key.pem"
#     public_key_path = "public_key.pem"
#
#     # Load the private key
#     private_key = load_private_key(private_key_path)
#     print(f"Loaded Private Key: {private_key}")
#
#     # Load the public key
#     public_key = load_public_key(public_key_path)
#     print(f"Loaded Public Key: {public_key}")
#
#     # Encrypt the data
#     encrypted = encrypt_with_aes(original_data)
#     print("Encrypted Data:", encrypted)
#
#     # Decrypt the data
#     decrypted = aes_decrypt(encrypted)
#     print("Decrypted Data:", decrypted)
#
#     # Verify the result
#     assert decrypted == original_data, "Decryption failed! Data does not match."
#     print("Decryption successful!")
#
# #"""