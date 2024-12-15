class Message:
    def __init__(self, senders_phone_number, targets_phone_number, senders_public_key,
                 aes_wrapped_key, iv, encrypted_content):
        self.senders_phone_number = senders_phone_number  # Sender's phone number
        self.targets_phone_number = targets_phone_number  # Target's phone number
        self.senders_public_key = senders_public_key  # Sender's public key
        self.aes_wrapped_key = aes_wrapped_key  # Encrypted AES key
        self.iv = iv  # Initialization vector (not encrypted)
        self.encrypted_content = encrypted_content  # Encrypted content of the message

    # Setters
    def set_senders_phone_number(self, senders_phone_number):
        """Set the sender's phone number."""
        self.senders_phone_number = senders_phone_number

    def set_targets_phone_number(self, targets_phone_number):
        """Set the target's phone number."""
        self.targets_phone_number = targets_phone_number

    def set_senders_public_key(self, senders_public_key):
        """Set the sender's public key."""
        self.senders_public_key = senders_public_key

    def set_aes_wrapped_key(self, aes_wrapped_key):
        """Set the AES wrapped key (encrypted with a derived key)."""
        self.aes_wrapped_key = aes_wrapped_key

    def set_iv(self, iv):
        """Set the initialization vector (IV)."""
        self.iv = iv

    def set_encrypted_content(self, encrypted_content):
        """Set the encrypted content of the message."""
        self.encrypted_content = encrypted_content

    # Getters
    def get_senders_phone_number(self):
        """Get the sender's phone number."""
        return self.senders_phone_number

    def get_targets_phone_number(self):
        """Get the target's phone number."""
        return self.targets_phone_number

    def get_senders_public_key(self):
        """Get the sender's public key."""
        return self.senders_public_key

    def get_aes_wrapped_key(self):
        """Get the AES wrapped key (encrypted with a derived key)."""
        return self.aes_wrapped_key

    def get_iv(self):
        """Get the initialization vector (IV)."""
        return self.iv

    def get_encrypted_content(self):
        """Get the encrypted content of the message."""
        return self.encrypted_content


