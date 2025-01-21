from user_side.user_utils import load_public_key


class User:
    def __init__(self, phone_number, public_key, secret_code_hash):
        self.phone_number = phone_number  # String or int
        self.public_key = public_key  # Public key (e.g., string or bytes)
        self.secret_code_hash = secret_code_hash  # Secret code for verification/authentication
        self.waiting_messages = []  # List to store messages (list of Message objects)

    # Getters
    def get_public_key(self):
        """Get the user's public key."""
        print(f'PUBLIC KEY IS TYPE {type(self.public_key)}')
        return self.public_key

    def get_phone_number(self):
        """Get the user's phone number."""
        return self.phone_number

    def get_secret_code_hash(self):
        return self.secret_code_hash

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

    def get_waiting_messages(self):
        """
        Returns the list of waiting messages for the user.

        Returns:
            list: List of messages.
        """
        return self.waiting_messages
