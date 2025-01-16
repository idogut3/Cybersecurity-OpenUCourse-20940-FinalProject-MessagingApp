import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey


def serialize_private_ecc_key_to_pem_format(private_ecc_key: EllipticCurvePrivateKey):
    private_key_pem = private_ecc_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()  # No password protection
    )

    return private_key_pem


def serialize_public_ecc_key_to_pem_format(public_ecc_key: EllipticCurvePublicKey):
    public_key_pem = public_ecc_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return public_key_pem


def deserialize_pem_to_ecc_public_key(pem_data: bytes) -> ec.EllipticCurvePublicKey:
    """
    Deserialize PEM-encoded ECC public key data back into an EllipticCurvePublicKey object.

    Args:
        pem_data (bytes): The PEM-encoded ECC public key data.

    Returns:
        EllipticCurvePublicKey: The deserialized ECC public key object.
    """
    try:
        public_key = serialization.load_pem_public_key(pem_data)
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            return public_key
        else:
            raise ValueError("The PEM data does not represent a valid ECC public key.")
    except ValueError as e:
        raise ValueError(f"Failed to deserialize the PEM data into an ECC public key: {e}")


def deserialize_pem_to_ecc_private_key(pem_data: bytes) -> ec.EllipticCurvePrivateKey:
    """
    Deserialize PEM-encoded ECC private key data back into an EllipticCurvePrivateKey object.

    Args:
        pem_data (bytes): The PEM-encoded ECC private key data.

    Returns:
        EllipticCurvePrivateKey: The deserialized ECC private key object.
    """
    try:
        private_key = serialization.load_pem_private_key(pem_data, password=None)
        if isinstance(private_key, ec.EllipticCurvePrivateKey):
            return private_key
        else:
            raise ValueError("The PEM data does not represent a valid ECC private key.")
    except ValueError as e:
        raise ValueError(f"Failed to deserialize the PEM data into an ECC private key: {e}")


def save_keys_to_files(ecc_keys_file_path: str, public_key, private_key):
    """
    Saves the ECC keys to files.
    Args:
        public_key (ec.EllipticCurvePublicKey): The public ECC key to save.
        private_key (ec.EllipticCurvePrivateKey): The private ECC key to save.
        ecc_keys_file_path: The directory location in which we want to save the keys in.

    """
    # Ensure the directory exists
    os.makedirs(ecc_keys_file_path, exist_ok=True)

    public_key_path = os.path.join(ecc_keys_file_path, "public_key.pem")
    private_key_path = os.path.join(ecc_keys_file_path, "private_key.pem")
    # Save public key
    with open(public_key_path, "wb") as public_file:
        public_file.write(serialize_public_ecc_key_to_pem_format(public_key))

    # Save private key
    with open(private_key_path, "wb") as private_file:
        private_file.write(serialize_private_ecc_key_to_pem_format(private_key))


def load_private_key_from_file(file_path):
    """
    Loads a private key from a PEM file.
    Args:
        file_path (str): Path to the PEM file.
    Returns:
        rsa.RSAPrivateKey: The loaded private key.
    """
    with open(file_path, "rb") as private_file:
        private_key = serialization.load_pem_private_key(
            private_file.read(),
            password=None
        )
    return private_key


def load_public_key_from_file(file_path):
    """
    Loads a public key from a PEM file.
    Args:
        file_path (str): Path to the PEM file.
    Returns:
        rsa.RSAPublicKey: The loaded public key.
    """
    with open(file_path, "rb") as public_file:
        public_key = serialization.load_pem_public_key(public_file.read())
    return public_key
