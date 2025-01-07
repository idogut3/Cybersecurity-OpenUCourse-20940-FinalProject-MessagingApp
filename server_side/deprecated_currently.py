# from cryptography.hazmat.primitives.asymmetric import rsa, padding
# from cryptography.hazmat.primitives import serialization, hashes
#
# def generate_rsa_keys():
#     """
#     Generates RSA public and private keys.
#     Returns:
#         private_key (rsa.RSAPrivateKey): The RSA private key.
#         public_key (rsa.RSAPublicKey): The RSA public key.
#     """
#     private_key = rsa.generate_private_key(
#         public_exponent=65537,
#         key_size=2048
#     )
#     public_key = private_key.public_key()
#     return private_key, public_key
#
# def encrypt_message(message, public_key):
#     """
#     Encrypts a message using the RSA public key.
#     Args:
#         message (str): The message to encrypt.
#         public_key (rsa.RSAPublicKey): The RSA public key.
#     Returns:
#         bytes: The encrypted message.
#     """
#     message_bytes = message.encode('utf-8')
#     encrypted_message = public_key.encrypt(
#         message_bytes,
#         padding.OAEP(
#             mgf=padding.MGF1(algorithm=hashes.SHA256()),
#             algorithm=hashes.SHA256(),
#             label=None
#         )
#     )
#     return encrypted_message
#
# def decrypt_message(encrypted_message, private_key):
#     """
#     Decrypts an encrypted message using the RSA private key.
#     Args:
#         encrypted_message (bytes): The encrypted message.
#         private_key (rsa.RSAPrivateKey): The RSA private key.
#     Returns:
#         str: The decrypted message.
#     """
#     decrypted_message = private_key.decrypt(
#         encrypted_message,
#         padding.OAEP(
#             mgf=padding.MGF1(algorithm=hashes.SHA256()),
#             algorithm=hashes.SHA256(),
#             label=None
#         )
#     )
#     return decrypted_message.decode('utf-8')
#
# def save_keys_to_files(private_key, public_key):
#     """
#     Saves the RSA keys to files.
#     Args:
#         private_key (rsa.RSAPrivateKey): The private key to save.
#         public_key (rsa.RSAPublicKey): The public key to save.
#     """
#     # Save private key
#     with open("private_key.pem", "wb") as private_file:
#         private_file.write(
#             private_key.private_bytes(
#                 encoding=serialization.Encoding.PEM,
#                 format=serialization.PrivateFormat.PKCS8,
#                 encryption_algorithm=serialization.NoEncryption()
#             )
#         )
#
#     # Save public key
#     with open("public_key.pem", "wb") as public_file:
#         public_file.write(
#             public_key.public_bytes(
#                 encoding=serialization.Encoding.PEM,
#                 format=serialization.PublicFormat.SubjectPublicKeyInfo
#             )
#         )
#
# def public_key_to_json(public_key):
#     """
#     Converts a public key to a JSON-serializable format.
#     Args:
#         public_key (rsa.RSAPublicKey): The public key to convert.
#     Returns:
#         str: The public key
#     """
#     public_key_pem = public_key.public_bytes(
#         encoding=serialization.Encoding.PEM,
#         format=serialization.PublicFormat.SubjectPublicKeyInfo
#     ).decode('utf-8')
#     return public_key_pem
#
# def private_key_from_file(file_path):
#     """
#     Loads a private key from a PEM file.
#     Args:
#         file_path (str): Path to the PEM file.
#     Returns:
#         rsa.RSAPrivateKey: The loaded private key.
#     """
#     with open(file_path, "rb") as private_file:
#         private_key = serialization.load_pem_private_key(
#             private_file.read(),
#             password=None
#         )
#     return private_key
#
# def public_key_from_file(file_path):
#     """
#     Loads a public key from a PEM file.
#     Args:
#         file_path (str): Path to the PEM file.
#     Returns:
#         rsa.RSAPublicKey: The loaded public key.
#     """
#     with open(file_path, "rb") as public_file:
#         public_key = serialization.load_pem_public_key(public_file.read())
#     return public_key
#
# # Example usage:
# if __name__ == "__main__":
#     # Generate keys
#     private_key, public_key = generate_rsa_keys()
#
#     # Save keys to files (optional)
#     save_keys_to_files(private_key, public_key)
#
#     # Message to encrypt
#     original_message = "This is a secret message."
#     print(f"Original message: {original_message}")
#
#     # Encrypt the message
#     encrypted = encrypt_message(original_message, public_key_from_file("public_key.pem"))
#     print(f"Encrypted message: {encrypted}")
#
#     # Decrypt the message
#     decrypted = decrypt_message(encrypted, private_key_from_file("private_key.pem"))
#     print(f"Decrypted message: {decrypted}")
