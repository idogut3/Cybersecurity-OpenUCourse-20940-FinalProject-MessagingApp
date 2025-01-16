# from user_side.user_utils import make_directory
from GlobalCryptoUtils import generate_ecc_keys
from GlobalValidations import validate_email, validate_phone_number


class User:
    # users_created = 0

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
        self.server_public_key = None
        # User.users_created += 1
        # self.directory_path = "Cybersecurity-OpenUCourse-20940-FinalProject-MessagingApp\\user_side\\users\\" + str(
        #     User.users_created)
        # make_directory(self.directory_path)

    def get_version(self):
        return self.version

    def get_public_key(self):
        return self.public_key

    def set_server_public_key(self, server_public_key):
        self.server_public_key = server_public_key

    def get_server_public_key(self):
        return self.server_public_key

    def get_private_key(self):
        return self.private_key

    def get_phone_number(self):
        return self.phone_number

    def set_phone_number(self, phone_number):
        self.phone_number = phone_number

    def get_email(self):
        return self.email

    def set_email(self, email):
        self.email = email

    def get_code(self):
        return self.code

    def set_code(self, code):
        self.code = code

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



def get_email_validated():
    validated_email = False
    email = ""
    while not validated_email:
        email = input("Enter your email: ")
        validated_email = validate_email(email)

        if not validated_email:
            print("Invalid email. Please try again.")
    return email

def get_validated_phone_number():
    validated_phone_number = False
    phone_number = ""

    # Loop until a valid phone number is provided
    while not validated_phone_number:
        phone_number = input("Enter your phone number: ")
        validated_phone_number = validate_phone_number(phone_number)

        if not validated_phone_number:
            print("Invalid phone number. Please try again.")

    return phone_number

def create_user() -> User:
    USER_VERSION = 3

    email = get_email_validated()
    phone_number = get_validated_phone_number()

    public_key , private_key = generate_ecc_keys()
    new_user = User(version=USER_VERSION, public_key = public_key, private_key= private_key, email= email, phone_number=phone_number)
    return new_user
