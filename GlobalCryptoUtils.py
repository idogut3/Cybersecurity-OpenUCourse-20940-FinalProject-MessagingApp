import os
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.asymmetric.ec import ECDH, EllipticCurvePublicKey, EllipticCurvePrivateKey
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def generate_ecc_keys() -> tuple[EllipticCurvePublicKey, EllipticCurvePrivateKey]:
    # Generate ECC private key
    private_key = ec.generate_private_key(ec.SECP256R1())

    # Get the associated public key
    public_key = private_key.public_key()

    return public_key, private_key

def generate_aes_key(key_size=32) -> bytes:
    """
        Generates a new random AES key. NOTE: leave key_size = 32 to for AES-256!!!

        The key size can be specified. The default size is 256 bits.

        Args:
            key_size (int): The size of the AES key in bits. Must be either 16 (AES-128), 24 (AES-192), or 32 (AES-256)

        Returns:
            bytes: A randomly generated AES key.
        """
    aes_key = os.urandom(key_size)
    return aes_key


def generate_random_iv() -> bytes:
    """
        Generates a random 16-byte IV for AES encryption.

        Returns:
            bytes: A securely generated random IV.
        """
    iv_size = 16  # AES block size is always 16 bytes
    return os.urandom(iv_size)


def create_shared_secret(receiver_public_key:EllipticCurvePublicKey, sender_private_key:EllipticCurvePrivateKey) -> bytes:
    """
    Creates a shared secret using ECDH key exchange.

    Args:
        receiver_public_key (EllipticCurvePublicKey): The sender's public key.
        sender_private_key (EllipticCurvePrivateKey): The receiver's private key.

    Returns:
        bytes: The shared secret.
    """
    # Generate the raw shared key using ECDH
    shared_key = sender_private_key.exchange(ECDH(), receiver_public_key)

    return shared_key


def generate_salt(length=16):
    """
    Generates a cryptographically secure random salt.

    Parameters:
        length (int): The length of the salt in bytes. Default is 16 bytes.
                     Common lengths: 16, 32, or 64 bytes.

    Returns:
        bytes: A securely generated random salt.
    """
    if length <= 0:
        raise ValueError("Salt length must be a positive integer.")
    return os.urandom(length)

def kdf_wrapper(shared_secret: bytes, salt: bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=1000000,
    )
    return kdf.derive(shared_secret)


def wrap_cbc_aes_key(aes_key:bytes, kdf_wrapped_shared_secret:bytes):
    """
        Encrypts (wraps) an AES key using AES-CBC with a KDF-wrapped shared secret.

        Args:
            aes_key (bytes): The AES key to be wrapped (16, 24, or 32 bytes).
            kdf_wrapped_shared_secret (bytes): The derived key from KDF (32 bytes).

        Returns:
            tuple: The wrapped AES key (ciphertext) and the IV used for encryption.
        """
    # Ensure the AES key is padded to match the block size (16 bytes)
    KEY_BLOCK_SIZE = 16
    iv = generate_random_iv()

    # Create AES-CBC cipher
    cipher = Cipher(algorithms.AES(kdf_wrapped_shared_secret), modes.CBC(iv))
    encryptor = cipher.encryptor()

    pad_length = KEY_BLOCK_SIZE - (len(aes_key) % KEY_BLOCK_SIZE)
    padded_aes_key = aes_key + bytes([pad_length] * pad_length)

    # Encrypt the AES key
    wrapped_aes_key = encryptor.update(padded_aes_key) + encryptor.finalize()

    return {"wrapped_aes_key": wrapped_aes_key, "iv:": iv}


def unwrap_cbc_aes_key(wrapped_aes_key:bytes, kdf_wrapped_shared_secret:bytes, iv:bytes):
    """
    Decrypts (unwraps) an AES key using AES-CBC with a KDF-wrapped shared secret an iv.

    Args:
        wrapped_aes_key (bytes): The wrapped AES key (ciphertext).
        kdf_wrapped_shared_secret (bytes): The derived key from KDF (32 bytes).
        iv (bytes): The IV used during encryption.

    Returns:
        bytes: The original AES key.
    """
    # Create AES-CBC cipher
    cipher = Cipher(algorithms.AES(kdf_wrapped_shared_secret), modes.CBC(iv))
    cipher_cbc_decryptor = cipher.decryptor()

    # Decrypt to retrieve the padded AES key
    padded_aes_key = cipher_cbc_decryptor.update(wrapped_aes_key) + cipher_cbc_decryptor.finalize()

    # Remove padding
    pad_length = padded_aes_key[-1]
    aes_key = padded_aes_key[:-pad_length]

    return aes_key


def encrypt_message_with_aes_cbc_key(message, aes_key, iv): #TODO: MAKE THIS ENCRYPT A JSON FILE INSTEAD
    """
    Encrypts a message using AES-CBC.

    Args:
        message (bytes): The plaintext message to be encrypted.
        aes_key (bytes): The AES key (16, 24, or 32 bytes).
        iv (bytes): The Initialization Vector (IV) for AES-CBC (16 bytes).

    Returns:
        bytes: The encrypted message (ciphertext).
    """
    # Ensure the AES key length is valid for AES (128, 192, or 256 bits)
    assert len(aes_key) in [16, 24, 32], "Invalid AES key length. Must be 16, 24, or 32 bytes."

    # Create AES-CBC cipher
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Pad the message to be a multiple of block size (16 bytes) using PKCS7
    block_size = 16
    pad_length = block_size - (len(message) % block_size)
    padded_message = message + bytes([pad_length] * pad_length)

    # Encrypt the message
    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()

    return encrypted_message


# def aes_decrypt(encrypted_data: dict) -> bytes: # TODO: PROBABLY NOT NEEDED BUT I AM SAVING IT IN THE CODE JUST IN CASE ~idogut3
#     """
#     Decrypts the data encrypted by aes_encrypt.
#
#     Args:
#         encrypted_data (dict): Dictionary containing the key, iv, and ciphertext.
#
#     Returns:
#         bytes: The original plaintext data.
#     """
#     key = encrypted_data["key"]
#     iv = encrypted_data["iv"]
#     ciphertext = encrypted_data["ciphertext"]
#
#     # Create a Cipher object using the key and IV
#     cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
#     decryptor = cipher.decryptor()
#
#     # Decrypt the ciphertext
#     padded_message = decryptor.update(ciphertext) + decryptor.finalize()
#
#     # Remove the PKCS7 padding
#     unpad = padding.PKCS7(128).unpadder()
#     plaintext = unpad.update(padded_message) + unpad.finalize()
#
#     return plaintext

def decrypt_message_with_aes_cbc_key(encrypted_message, aes_key, iv): #TODO: MAKE THIS DECRYPT TO A JSON FILE INSTEAD
    """
    Decrypts an encrypted message using AES-CBC.

    Args:
        encrypted_message (bytes): The encrypted message (ciphertext) to be decrypted.
        aes_key (bytes): The AES key (16, 24, or 32 bytes).
        iv (bytes): The Initialization Vector (IV) for AES-CBC (16 bytes).

    Returns:
        bytes: The decrypted message (plaintext).
    """
    # Ensure the AES key length is valid for AES (128, 192, or 256 bits)
    assert len(aes_key) in [16, 24, 32], "Invalid AES key length. Must be 16, 24, or 32 bytes."

    # Create AES-CBC cipher
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    cipher_cbc_decryptor = cipher.decryptor()

    # Decrypt the message
    decrypted_message = cipher_cbc_decryptor.update(encrypted_message) + cipher_cbc_decryptor.finalize()

    # Remove PKCS7 padding
    pad_length = decrypted_message[-1]
    decrypted_message = decrypted_message[:-pad_length]

    return decrypted_message
