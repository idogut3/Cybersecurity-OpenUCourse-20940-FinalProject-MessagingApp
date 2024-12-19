import os

from cryptography.hazmat.primitives.asymmetric.ec import  EllipticCurvePublicKey, EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

server_ip = "127.0.0.1"  # Server IP
server_port = 5000  # Server port

def generate_ecc_keys(private_key_file: str, public_key_file: str):
    # Generate ECC private key
    private_key = ec.generate_private_key(ec.SECP256R1())

    # Get the associated public key
    public_key = private_key.public_key()

    # Serialize the private key to PEM format
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()  # No password protection
    )

    # Serialize the public key to PEM format
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Save the private key to a file
    with open(private_key_file, "wb") as private_file:
        private_file.write(private_key_pem)

    # Save the public key to a file
    with open(public_key_file, "wb") as public_file:
        public_file.write(public_key_pem)

    return {
        "public_key_pem": public_key_pem.decode("utf-8"),
        "private_key_pem": private_key_pem.decode("utf-8")
    }

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


def aes_encrypt(data: bytes) -> dict:
    key = os.urandom(32)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    pad = padding.PKCS7(128).padder()
    padded_message = pad.update(data) + pad.finalize()
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    return {
        "key": key,
        "iv": iv,
        "ciphertext": ciphertext
    }


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

def do_kdf(shared_secret: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=1000000,
    )
    return kdf.derive(shared_secret)

def wrap_aes_key_with_derived_key(aes_key: bytes, derived_key: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(derived_key), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(aes_key) + encryptor.finalize()

def unwrap_aes_key_with_derived_key(aes_key: bytes, derived_key: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(derived_key), modes.ECB())
    decryptor = cipher.decryptor()
    return decryptor.update(aes_key) + decryptor.finalize()
#"""
if __name__ == "__main__":
    # Original plaintext data
    original_data = b"Sensitive information to encrypt!"
    # Call the function to generate and save keys
    generate_ecc_keys(private_key_file="private_key.pem", public_key_file="public_key.pem")
    # Paths to the key files
    private_key_path = "private_key.pem"
    public_key_path = "public_key.pem"

    # Load the private key
    private_key = load_private_key(private_key_path)
    print(f"Loaded Private Key: {private_key}")

    # Load the public key
    public_key = load_public_key(public_key_path)
    print(f"Loaded Public Key: {public_key}")

    # Encrypt the data
    encrypted = aes_encrypt(original_data)
    print("Encrypted Data:", encrypted)

    # Decrypt the data
    decrypted = aes_decrypt(encrypted)
    print("Decrypted Data:", decrypted)

    # Verify the result
    assert decrypted == original_data, "Decryption failed! Data does not match."
    print("Decryption successful!")

#"""