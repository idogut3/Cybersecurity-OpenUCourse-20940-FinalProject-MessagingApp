import os
import random
from cryptography.hazmat.primitives.asymmetric.ec import  EllipticCurvePublicKey, EllipticCurvePrivateKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


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

def generate_random_code():
    """
    Generates a 6-digit random code.

    Returns:
        str: A 6-digit random code as a string.
    """
    return ''.join(random.choices("0123456789", k=6))

def make_directory(directory_name):
    """
       Creates a new directory with the specified name.

       Args:
           directory_name (str): The name of the directory to create.

       If the directory already exists, no action is taken. If there is an error
       creating the directory, an error message is printed.
    """
    try:  # Was able to create users directory
        os.makedirs(directory_name)
    except OSError as error:  # Error couldn't create directory
        print(error)