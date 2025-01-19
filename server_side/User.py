class User:
    def __init__(self, phone_number, public_key, secret_code):
        self.phone_number = phone_number  # String or int
        self.public_key = public_key  # Public key (e.g., string or bytes)
        self.secret_code = secret_code  # Secret code for verification/authentication
        self.waiting_messages = []  # List to store messages (list of Message objects)

    # Getters
    def get_public_key(self):
        """Get the user's public key."""
        return self.public_key

    def get_phone_number(self):
        """Get the user's phone number."""
        return self.phone_number

    def add_message(self, message):
        """
        Adds a message to the user's waiting messages.

        Args:
            message: The message object or string to add.
        """
        self.waiting_messages.append(message)

    def clear_messages(self):
        """
        Clears all the user's waiting messages.
        """
        self.waiting_messages.clear()