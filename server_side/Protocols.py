from abc import ABC, abstractmethod
import json

from server_side.crypto_utils import public_key_from_file, decrypt_message, private_key_from_file
from server_side.database_utils import validate_phone_number
from server_side.utils import SERVER_IP, SERVER_PORT, send_json, generate_random_code


# Abstract Class: Protocol
class Protocol(ABC):
    def __init__(self, server=None, conn=None, database=None):
        self.json = None      # Placeholder for JSON handling logic
        self.server = server  # IP and port information
        self.conn = conn      # Connection object (e.g., socket)
        self.database = database  # Placeholder for database access

    @abstractmethod
    def protocol(self):
        """Abstract method that must be implemented by derived classes."""
        pass


# ---------------------------
# 3. Define Subclasses
# ---------------------------
class RegisterRequestProtocol(Protocol):
    def protocol(self):
        """Implementation of the protocol method."""
        print("Executing RegisterRequestProtocol protocol.")
        response_dict = self.process_send_public_key_to_user()
        if response_dict.get("code") != "We":
            return 1
        phone_number = decrypt_message(response_dict.get("phone_number"), private_key_from_file("private_key.pem"))
        if not validate_phone_number(phone_number):
            return 1
        random_code = generate_random_code()
        self.process_register_request()


    def process_send_public_key_to_user(self):
        data_to_send = {
            "code": "We",
            "public_key": public_key_from_file("public_key.pem")
        }

        recived_data = send_json(SERVER_IP, SERVER_PORT,
                                 data_to_send)  # the server should send a json with the same code and his public key.

        return json.loads(recived_data)



    def process_register_request(self):
        """Process the register request logic."""
        print("Processing register request...")
        # You can implement your registration logic here,
        # e.g., self.database.insert_user(self.json["username"], ...)
        # Then send a response if needed:
        response = json.dumps({"status": "registered"}).encode('utf-8')
        self.conn.sendall(response)


class ConnectRequestProtocol(Protocol):
    def protocol(self):
        """Implementation of the protocol method."""
        print("Executing ConnectRequestProtocol protocol.")
        self.process_connect_request()

    def process_connect_request(self):
        """Process the connect request logic."""
        print("Processing connect request...")
        # Possibly verify credentials, etc.
        response = json.dumps({"status": "connected"}).encode('utf-8')
        self.conn.sendall(response)


class CheckWaitingMessagesProtocol(Protocol):
    def protocol(self):
        """Implementation of the protocol method."""
        print("Executing CheckWaitingMessagesProtocol protocol.")
        self.process_check_user_waiting_messages()

    def process_check_user_waiting_messages(self):
        """Process the logic to check user waiting messages."""
        print("Checking user waiting messages...")
        # Query the database for messages, etc.
        response = json.dumps({"status": "messages_checked"}).encode('utf-8')
        self.conn.sendall(response)


class ProcessCommunicateProtocol(Protocol):
    def protocol(self):
        """Implementation of the protocol method."""
        print("Executing ProcessCommunicateProtocol protocol.")
        self.process_communicate()

    def process_communicate(self):
        """Process the communication logic."""
        print("Processing communication...")
        # Handle sending/receiving messages
        response = json.dumps({"status": "message_processed"}).encode('utf-8')
        self.conn.sendall(response)
