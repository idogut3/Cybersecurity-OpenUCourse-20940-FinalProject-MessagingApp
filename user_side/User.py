class User:
    def __init__(self, version, public_key, private_key, phone_number):
        self.version = version  # Application or protocol version
        self.connections = {}  # Dictionary to store connections (phone_number -> User object)
        self.public_key = public_key  # User's public key
        self.private_key = private_key  # User's private key
        self.phone_number = phone_number  # User's phone number
        self.code = 0  # Initialized as 0, updated when registered
        self.is_connected_to_server = False  # Boolean to track server connection status
        self.waiting_messages = []  # List of messages waiting to be processed

    def display_options(self):
        """Display available user options (CLI-based implementation)."""
        print("1. Register to server")
        print("2. Connect to server")
        print("3. Add new connection")
        print("4. Send message")
        print("5. Show waiting messages")

    def register_to_server(self):
        """Register the user to the server."""
        pass  # Implement the logic for server registration

    def connect_to_server(self):
        """Connect the user to the server."""
        pass  # Implement the logic for server connection

    def is_connected_to(self, phone_number):
        """Check if the user is connected to another user by phone number."""
        return phone_number in self.connections

    def add_new_connection(self, new_connection):
        """
        Add a new connection to the user's connections dictionary.

        Args:
            new_connection (User): The new connection to be added.
        """
        if new_connection.phone_number:
            self.connections[new_connection.phone_number] = new_connection
        else:
            print("Error: The new connection does not have a valid phone number.")

    def send_message_to(self, phone_number):
        """
        Send a message to another user by phone number.

        Args:
            phone_number (str): The phone number of the recipient.
        """
        pass  # Implement the logic for sending a message

    def show_waiting_messages(self):
        """Display all waiting messages."""
        if not self.waiting_messages:
            print("No waiting messages.")
        else:
            print("Waiting Messages:")
            for message in self.waiting_messages:
                print(message)  # Assuming Message class has a suitable __str__ method
