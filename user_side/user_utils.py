import os

from cryptography.hazmat.primitives.asymmetric.ec import  EllipticCurvePublicKey, EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding

def generate_ecc_keys():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return {
        "public": public_key,
        "private": private_key
    }

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



def create_shared_secret(our_private_key:
    EllipticCurvePrivateKey, their_public_key: EllipticCurvePublicKey) -> bytes:
    return our_private_key.exchange(ec.ECDH(), their_public_key)

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
"""
if __name__ == "__main__":
    # Original plaintext data
    original_data = b"Sensitive information to encrypt!"

    # Encrypt the data
    encrypted = aes_encrypt(original_data)
    print("Encrypted Data:", encrypted)

    # Decrypt the data
    decrypted = aes_decrypt(encrypted)
    print("Decrypted Data:", decrypted)

    # Verify the result
    assert decrypted == original_data, "Decryption failed! Data does not match."
    print("Decryption successful!")

"""