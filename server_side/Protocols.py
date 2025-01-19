import socket
from abc import ABC, abstractmethod
from math import expm1

from CommunicationCodes import GeneralCodes, UserSideRequestCodes, ServerSideProtocolCodes
from CommunicationUtils import send_dict_as_json_through_established_socket_connection, \
    receive_json_as_dict_through_established_connection
from GlobalCryptoUtils import create_shared_secret, kdf_wrapper, unwrap_cbc_aes_key, decrypt_message_with_aes_cbc_key
from GlobalValidations import is_valid_phone_number
from KeyLoaders import deserialize_pem_to_ecc_public_key, serialize_public_ecc_key_to_pem_format
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
        message_dict = {"code": GeneralCodes.GENERAL_SERVER_ERROR.value,
                        "error_description": error_description}
        send_dict_as_json_through_established_socket_connection(conn=self.conn, data=message_dict)


class RegisterRequestProtocol(Protocol):
    def run(self):
        print("Executing RegisterRequestProtocol protocol")
        error_message = "General Server Error"
        try:
            server_public_key = self.server.get_public_key()
            # server_private_key = self.server.get_private_key()
            try:
                self.send_public_key_to_user(server_public_key)
                print("SERVER SENT USER PUBLIC KEY")
            except OSError as error:
                print(f"Failed to send public key to user, error {error}")
                self.send_general_server_error(f"Failed to send public key to user, error {error}")

            send_phone_number_request_dict = receive_json_as_dict_through_established_connection(self.conn)

            if send_phone_number_request_dict[
                "code"] != UserSideRequestCodes.SEND_PHONE_NUMBER.value:
                error_message = "Wrong code, expected SEND_PHONE_NUMBER_REQUEST code"
                raise
            if not "phone_number" in send_phone_number_request_dict:
                error_message = "No phone number value in dict received replying to  SEND_PHONE_NUMBER_REQUEST"
                raise
            print("SERVER RECEIVED PHONE NUMBER FROM USER")
            phone_number = send_phone_number_request_dict["phone_number"]
            if not is_valid_phone_number(phone_number) and not self.database.is_user_registered(phone_number):
                error_message = "Phone number is not validated"
                raise
            print("PHONE NUMBER FROM USER IS VALIDATED")
            random_code = generate_random_code()
            send_by_secure_channel(random_code)

            send_public_key_request_dict = receive_json_as_dict_through_established_connection(self.conn)

            if send_public_key_request_dict[
                "code"] != UserSideRequestCodes.SEND_PUBLIC_KEY.value:
                error_message = "Wrong code, expected SEND_PUBLIC_KEY_REQUEST code"
                raise
            if not "public_key" in send_public_key_request_dict:
                error_message = "No public_key value in dict received replying to  SEND_PUBLIC_KEY_REQUEST"
                raise

            print("SERVER RECEIVED PUBLIC KEY FROM USER")
            user_public_key_pem = send_public_key_request_dict["public_key"]
            user_public_key = user_public_key_pem
            self.database.register_user(phone_number=phone_number, public_key=user_public_key, secret_code=random_code)
            print("SERVER REGISTERED A NEW USER")

            message_dict = {"code": ServerSideProtocolCodes.REGISTER_SUCCESS.value}
            send_dict_as_json_through_established_socket_connection(conn=self.conn, data=message_dict)

        except OSError:
            self.send_general_server_error(error_message)

    def send_public_key_to_user(self, public_key):
        message_dict = {
            "code": ServerSideProtocolCodes.SEND_PUBLIC_KEY.value,
            "public_key": str(serialize_public_ecc_key_to_pem_format(public_key))
        }
        send_dict_as_json_through_established_socket_connection(conn=self.conn, data=message_dict)


class ConnectRequestProtocol(Protocol):
    def run(self):
        print("Executing ConnectRequestProtocol protocol.")
        try:
            phone_number_received = self.request_dict["phone_number"]
            wrapped_aes_key = self.request_dict["wrapped_aes_key"]
            iv_for_wrapped_key = self.request_dict["iv_for_wrapped_key"]
            encrypted_secret_code = self.request_dict["encrypted_secret_code"]
            iv_for_secret = self.request_dict["iv_for_secret"]
            received_salt = self.request_dict["salt"]

            if not is_valid_phone_number(phone_number_received) or not self.database.is_user_registered(phone_number=phone_number_received):
                self.send_invalid_phone_number()
                return False

            user_public_key = self.database.get_public_key_by_phone_number(phone_number=phone_number_received)

            # Reconstruct the derived AES key using the same shared secret and salt
            shared_secret = create_shared_secret(user_public_key, self.server.get_private_key())
            reconstructed_encrypted_aes_key = kdf_wrapper(shared_secret, received_salt)

            decrypted_aes_key = unwrap_cbc_aes_key(wrapped_aes_key=wrapped_aes_key,
                                                   kdf_wrapped_shared_secret=reconstructed_encrypted_aes_key, iv=iv_for_wrapped_key)

            decrypted_secret_code = decrypt_message_with_aes_cbc_key(encrypted_message=encrypted_secret_code,
                                                                     aes_key=decrypted_aes_key,
                                                                     iv=iv_for_secret)


            user = self.database.get_user_by_phone_number(phone_number=phone_number_received)
            if not self.database.is_secret_code_correct_for_user(user = user, code=decrypted_secret_code):
                self.send_invalid_secret_code()
                return False

            print("CONNECT REQUEST APPROVED NEW USER")
            return True


        except OSError as error:
            print(f"Error at ConnectRequestProtocol {error}")
            self.send_general_server_error()

    def send_invalid_phone_number(self):
        message_dict = {
            "code": ServerSideProtocolCodes.INVALID_PHONE_NUMBER.value
        }
        send_dict_as_json_through_established_socket_connection(conn=self.conn, data=message_dict)

    def send_invalid_secret_code(self):
        message_dict = {
            "code": ServerSideProtocolCodes.INVALID_SECRET_CODE.value
        }
        send_dict_as_json_through_established_socket_connection(conn=self.conn, data=message_dict)

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
