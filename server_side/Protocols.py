import socket
from abc import ABC, abstractmethod

from CommunicationCodes import SubProcessCodes
from CommunicationUtils import send_dict_as_json_through_established_socket_connection, \
    receive_json_as_dict_through_established_connection
from GlobalValidations import validate_phone_number
from KeyLoaders import deserialize_pem_to_ecc_public_key
from server_side.utils import send_by_secure_channel
from user_side.user_utils import generate_random_code


class Protocol(ABC):
    def __init__(self, server, conn: socket.socket, request_dict: dict):
        self.request_dict = request_dict
        self.server = server
        self.database = server.get_database()  # Placeholder for database access
        self.conn = conn  # Connection object between the server and the user

    @abstractmethod
    def run(self):
        """The abstract method for running a protocol"""
        pass

    def send_general_server_error(self, error_description="General Server Error"):
        message_dict = {"code": SubProcessCodes.GeneralCodes.GENERAL_SERVER_ERROR.value,
                        "error_description": error_description}
        send_dict_as_json_through_established_socket_connection(conn=self.conn, data=message_dict)


class RegisterRequestProtocol(Protocol):
    def run(self):
        print("Executing RegisterRequestProtocol protocol")
        error_message = "General Server Error"
        try:
            server_public_key = self.server.get_public_key()
            server_private_key = self.server.get_private_key()
            try:
                self.send_public_key_to_user(server_public_key)
            except OSError as error:
                print(f"Failed to send public key to user, error {error}")
                self.send_general_server_error(f"Failed to send public key to user, error {error}")

            send_phone_number_request_dict = receive_json_as_dict_through_established_connection(self.conn)
            if send_phone_number_request_dict[
                "code"] != SubProcessCodes.UserSideRequestCodes.Registration.SEND_PHONE_NUMBER.value:
                error_message = "Wrong code, expected SEND_PHONE_NUMBER_REQUEST code"
                raise
            if not "phone_number" in send_phone_number_request_dict:
                error_message = "No phone number value in dict received replying to  SEND_PHONE_NUMBER_REQUEST"
                raise
            phone_number = send_phone_number_request_dict["phone_number"]
            if not validate_phone_number(phone_number) and not self.database.is_user_registered(phone_number):
                error_message = "Phone number is not validated"
                raise
            random_code = generate_random_code()
            send_by_secure_channel(random_code)
            send_public_key_request_dict = receive_json_as_dict_through_established_connection(self.conn)

            if send_public_key_request_dict[
                "code"] != SubProcessCodes.UserSideRequestCodes.Registration.SEND_PUBLIC_KEY.value:
                error_message = "Wrong code, expected SEND_PUBLIC_KEY_REQUEST code"
                raise
            if not "public_key_pem" in send_public_key_request_dict:
                error_message = "No public_key value in dict received replying to  SEND_PUBLIC_KEY_REQUEST"
                raise
            user_public_key_pem = send_public_key_request_dict["public_key"]
            user_public_key = deserialize_pem_to_ecc_public_key(user_public_key_pem)

            self.database.register_user(phone_number=phone_number, public_key=user_public_key, secret_code=random_code)

            message_dict = {"code": SubProcessCodes.ServerSideProtocolCodes.Registration.REGISTER_SUCCESS.value}
            send_dict_as_json_through_established_socket_connection(conn=self.conn, data=message_dict)

        except OSError:
            self.send_general_server_error(error_message)

    def send_public_key_to_user(self, public_key):
        message_dict = {
            "code": SubProcessCodes.ServerSideProtocolCodes.Registration.SEND_PUBLIC_KEY.value,
            "public_key": public_key
        }
        send_dict_as_json_through_established_socket_connection(conn=self.conn, data=message_dict)


class ConnectRequestProtocol(Protocol):
    def run(self):
        """Implementation of the protocol method."""
        print("Executing ConnectRequestProtocol protocol.")
    #     self.process_connect_request()
    #
    # def process_connect_request(self):
    #     """Process the connect request logic."""
    #     print("Processing connect request...")
    #     # Possibly verify credentials, etc.
    #     response = json.dumps({"status": "connected"}).encode('utf-8')
    #     self.conn.sendall(response)


class CheckWaitingMessagesProtocol(Protocol):
    def run(self):
        """Implementation of the protocol method."""
        print("Executing CheckWaitingMessagesProtocol protocol.")
    #     self.process_check_user_waiting_messages()
    #
    # def process_check_user_waiting_messages(self):
    #     """Process the logic to check user waiting messages."""
    #     print("Checking user waiting messages...")
    #     # Query the database for messages, etc.
    #     response = json.dumps({"status": "messages_checked"}).encode('utf-8')
    #     self.conn.sendall(response)


class ProcessCommunicateProtocol(Protocol):
    def run(self):
        """Implementation of the protocol method."""
        print("Executing ProcessCommunicateProtocol protocol.")
    #     self.process_communicate()
    #
    # def process_communicate(self):
    #     """Process the communication logic."""
    #     print("Processing communication...")
    #     # Handle sending/receiving messages
    #     response = json.dumps({"status": "message_processed"}).encode('utf-8')
    #     self.conn.sendall(response)
