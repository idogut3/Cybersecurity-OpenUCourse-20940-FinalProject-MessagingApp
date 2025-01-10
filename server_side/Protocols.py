import socket
from abc import ABC, abstractmethod
import json
from math import expm1

from server_side.Server import Server

class Protocol(ABC):
    def __init__(self, server: Server, conn: socket.socket, request_json):
        self.json = request_json
        self.server = server
        self.database = server.get_database()  # Placeholder for database access
        self.conn = conn  # Connection object between the server and the user

    @abstractmethod
    def run(self):
        """The abstract method for running a protocol"""
        pass
    def send_general_server_error(self):
        message =
        self.conn.sendall(message)


class RegisterRequestProtocol(Protocol):
    def run(self):
        print("Executing RegisterRequestProtocol protocol")
        try:
            self.send_public_key_to_user()
        except OSError as error:
            print(f"Failed to send public key to user, error {error}")

        # if response_dict.get("code") != "We":
        #     return 1
        # phone_number = decrypt_message(response_dict.get("phone_number"), private_key_from_file("private_key.pem"))
        # if not validate_phone_number(phone_number):
        #     return 1
        # random_code = generate_random_code()
        # self.process_register_request()

    def send_public_key_to_user(self):
        server_public_key =  self.server.ecc_keys[0]
        data_to_send = {
            "code": "We",
            "public_key": server_public_key
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
    def run(self):
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
    def run(self):
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
    def run(self):
        """Implementation of the protocol method."""
        print("Executing ProcessCommunicateProtocol protocol.")
        self.process_communicate()

    def process_communicate(self):
        """Process the communication logic."""
        print("Processing communication...")
        # Handle sending/receiving messages
        response = json.dumps({"status": "message_processed"}).encode('utf-8')
        self.conn.sendall(response)
