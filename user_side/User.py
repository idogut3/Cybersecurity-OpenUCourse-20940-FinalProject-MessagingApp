class User:
    def __init__(self, version, public_key, private_key, phone_number, email):
        """
        Initialize a User instance.

        Args:
            version (Integer): Application or protocol version.
            public_key (EllipticCurvePublicKey): User's public key.
            private_key (EllipticCurvePrivateKey): User's private key.
            phone_number (str): User's phone number.
        """
        self.version = version  # Application or protocol version
        self.connections = dict()  # Dictionary to store connections (phone_number -> kdf_shared_secret)
        self.public_key = public_key  # User's public key
        self.private_key = private_key  # User's private key
        self.phone_number = phone_number  # User's phone number
        self.email = email
        self.code = 0  # Initialized as 0, updated when registered
        self.is_connected_to_server = False  # Boolean to track server connection status
        self.waiting_messages = []  # List of messages waiting to be processed


    def is_connected_to(self, phone_number):
        """
        Check if the user is connected to another user by phone number.

        Args:
            phone_number (str): The phone number to check.

        Returns:
            bool: True if connected, False otherwise.
        """
        return phone_number in self.connections


    def add_new_connection(self, target_phone_number, kdf_shared_secret):
        """
        Add a new connection to the user's connections dictionary.

        Args:
            target_phone_number (str): The phone number of the target user.
            kdf_shared_secret (str): The shared secret (post-KDF) for secure communication.
        """
        if target_phone_number:
            self.connections[target_phone_number] = kdf_shared_secret
            print(f"Added connection to {target_phone_number} with shared secret.")
        else:
            print("Error: The target phone number is invalid.")


    def connect_to_server(self):
        """
        Connect the user to the server (login).
        """
        if self.is_connected_to_server:
            print(f"User {self.phone_number} is already connected to the server.")
            return

        # Simulate server connection logic
        self.is_connected_to_server = True
        print(f"User {self.phone_number} successfully connected to the server.")


    def disconnect_from_server(self):
        """
        Disconnect the user from the server (logout).
        """
        if not self.is_connected_to_server:
            print(f"User {self.phone_number} is not connected to the server.")
            return

        # Simulate server disconnection logic
        self.is_connected_to_server = False
        print(f"User {self.phone_number} successfully disconnected from the server.")


    def send_message_to(self, phone_number, message):
        """
        Send a message to another user by phone number.

        Args:
            phone_number (str): The phone number of the recipient.
            message (str): The message to be sent.
        """
        if not self.is_connected_to(phone_number):
            print(f"Error: No connection found with {phone_number}.")
            return

        # Retrieve the shared secret (kdf_shared_secret) for the connection
        kdf_shared_secret = self.connections[phone_number]

        # Simulate sending a message using the shared secret
        print(f"Sending message to {phone_number} using shared secret {kdf_shared_secret}: {message}")


    def show_waiting_messages(self):
        """Display all waiting messages."""
        if not self.waiting_messages:
            print("No waiting messages.")
        else:
            print("Waiting Messages:")
            for message in self.waiting_messages:
                print(message)  # Assuming Message class has a suitable __str__ method

    def clear_waiting_messages(self):
        self.waiting_messages = []


