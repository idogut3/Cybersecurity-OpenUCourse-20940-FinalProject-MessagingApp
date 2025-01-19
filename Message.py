from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey

from GlobalCryptoUtils import create_shared_secret, kdf_wrapper, unwrap_cbc_aes_key, decrypt_message_with_aes_cbc_key


class Message:
    def __init__(self, senders_phone_number: str, senders_public_key: EllipticCurvePublicKey, wrapped_aes_key: bytes,
                 iv_for_wrapped_key: bytes, encrypted_message: bytes,
                 iv_for_message: bytes, salt: bytes):
        """
                Initializes a Message object with all required components.

                Args:
                    senders_phone_number (str): The sender's phone number as a string.
                    senders_public_key (EllipticCurvePublicKey): The sender's public key in bytes.
                    wrapped_aes_key (bytes): The AES key wrapped with the recipient's public key.
                    iv_for_wrapped_key (bytes): The initialization vector (IV) for decrypting the wrapped key.
                    encrypted_message (bytes): The message encrypted using the AES key.
                    iv_for_message (bytes): The initialization vector (IV) for decrypting the encrypted message.
                    salt (bytes): The salt used for key derivation.
                """
        self.senders_phone_number = senders_phone_number
        self.senders_public_key = senders_public_key
        self.wrapped_aes_key = wrapped_aes_key
        self.iv_for_wrapped_key = iv_for_wrapped_key
        self.encrypted_message = encrypted_message
        self.iv_for_message = iv_for_message
        self.salt = salt

    # Getter for sender's phone number
    def get_senders_phone_number(self):
        return self.senders_phone_number

    # Getter for sender's public key
    def get_senders_public_key(self):
        return self.senders_public_key

    # Getter for wrapped AES key
    def get_wrapped_aes_key(self):
        return self.wrapped_aes_key

    # Getter for IV for wrapped key
    def get_iv_for_wrapped_key(self):
        return self.iv_for_wrapped_key

    # Getter for encrypted message
    def get_encrypted_message(self):
        return self.encrypted_message

    # Getter for IV for message
    def get_iv_for_message(self):
        return self.iv_for_message

    # Getter for salt
    def get_salt(self):
        return self.salt

    def decrypt_message(self, receiver_private_key: EllipticCurvePrivateKey) -> str:
        """
        Decrypts the message using the recipient's private key.

        Args:
            receiver_private_key (EllipticCurvePrivateKey): The recipient's private key.

        Returns:
            str: The decrypted message as a string.
        """
        try:
            # Step 1: Generate the shared secret using ECDH
            shared_secret = create_shared_secret(self.senders_public_key, receiver_private_key)

            # Step 2: Derive the AES key using KDF and the shared secret
            derived_key = kdf_wrapper(shared_secret, self.salt)

            # Step 3: Unwrap the AES key using the derived key and the IV for the wrapped key
            aes_key = unwrap_cbc_aes_key(self.wrapped_aes_key, derived_key, self.iv_for_wrapped_key)

            # Step 4: Decrypt the encrypted message using the unwrapped AES key and the IV for the message
            decrypted_message_bytes = decrypt_message_with_aes_cbc_key(
                self.encrypted_message, aes_key, self.iv_for_message
            )

            # Step 5: Convert the decrypted message bytes to a string
            decrypted_message = decrypted_message_bytes.decode('utf-8')

            return decrypted_message

        except Exception as e:
            raise ValueError(f"Failed to decrypt message: {e}")

    def display_decrypted_message(self, receiver_private_key: EllipticCurvePrivateKey):
        decrypted_message = self.decrypt_message(receiver_private_key)

        print("Message Received from: ", self.senders_phone_number)
        print("Is:\n", decrypted_message)

