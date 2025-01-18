import socket
import time
from abc import ABC, abstractmethod

from cryptography.hazmat.primitives.keywrap import aes_key_wrap

from CommunicationCodes import ProtocolCodes, GeneralCodes, ServerSideProtocolCodes, UserSideRequestCodes
from CommunicationConstants import SERVER_IP, SERVER_DEFUALT_PORT
from CommunicationUtils import send_dict_as_json_through_established_socket_connection, \
    receive_json_as_dict_through_established_connection
from GlobalCryptoUtils import create_shared_secret, kdf_wrapper, generate_aes_key, encrypt_message_with_aes_cbc_key, \
    generate_random_iv, wrap_cbc_aes_key, generate_salt
from KeyLoaders import serialize_public_ecc_key_to_pem_format
from user_side.User import User, get_validated_phone_number, get_email_validated
import re


class Request(ABC):
    def __init__(self, server_ip=SERVER_IP, server_port=SERVER_DEFUALT_PORT):
        self.server_ip = server_ip
        self.server_port = server_port
        try:
            self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.conn.connect((server_ip, server_port))
        except Exception as error:
            print(f"Failed to connect client socket, error: {error}")

    @abstractmethod
    def run(self):
        """The abstract method for running a request"""
        pass

    def send_general_client_error(self, error_description="General Client Error"):
        message_dict = {"code": GeneralCodes.GENERAL_CLIENT_ERROR.value,
                        "error_description": error_description}
        send_dict_as_json_through_established_socket_connection(conn=self.conn, data=message_dict)


def ask_user_if_received_secret_code():
    while True:
        answer = input("Have you received the secret code? (yes or no)")
        if answer == "yes":
            return
        else:
            answer = input("Do you want to continue waiting? (yes or no)")
            if answer == "no":
                print("ok, exiting")
                raise
            elif answer == "yes":
                print("ok waiting more...")
                time.sleep(5)


class RegisterRequest(Request):
    def __init__(self, user, server_ip=SERVER_IP, server_port=SERVER_DEFUALT_PORT):
        super().__init__(server_ip, server_port)
        self.user = user

    def run(self):
        try:
            message_dict = {
                "code": ProtocolCodes.init_RegistrationCode.value
            }
            send_dict_as_json_through_established_socket_connection(conn=self.conn, data=message_dict)
            print("USER SENT SERVER HIS REGISTER REQUEST")
            dict_received = receive_json_as_dict_through_established_connection(conn=self.conn)
            print("USER received RESPONSE [RECEIVED SERVER'S PUBLIC KEY] :", dict_received)
            if dict_received["code"] != ServerSideProtocolCodes.SEND_PUBLIC_KEY.value:
                raise ValueError("Wrong code received, was suppose to receive Registration.SEND_PUBLIC_KEY")
            if not "public_key" in dict_received:
                raise ValueError("No public_key value in dict received in Registration.SEND_PUBLIC_KEY")

            server_public_key = dict_received["public_key"]
            self.user.set_server_public_key(server_public_key)
            phone_number = self.user.get_phone_number()

            self.send_phone_number(phone_number=phone_number)
            print("USER SENT HIS PHONE NUMBER")
            ask_user_if_received_secret_code()

            users_public_key = self.user.get_public_key()

            self.send_public_key(users_public_key)
            print("USER SENT HIS PUBLIC KEY")
            register_request_dict = receive_json_as_dict_through_established_connection(self.conn)
            print(f"USER RECEIVED RESPONSE, {register_request_dict}")
            if not register_request_dict[
                       "code"] == ServerSideProtocolCodes.REGISTER_SUCCESS.value:
                print("Registration failed received")

            else:
                print("Registration successes")

        except OSError as error:
            print(f"Error in RegisterRequest {error}")
            self.send_general_client_error()

    def send_phone_number(self, phone_number):
        message_dict = {"code": UserSideRequestCodes.SEND_PHONE_NUMBER.value,
                        "phone_number": phone_number}
        send_dict_as_json_through_established_socket_connection(conn=self.conn, data=message_dict)

    def send_public_key(self, public_key):
        message_dict = {"code": UserSideRequestCodes.SEND_PUBLIC_KEY.value,
                        "public_key": str(serialize_public_ecc_key_to_pem_format(public_key))}
        send_dict_as_json_through_established_socket_connection(conn=self.conn, data=message_dict)


def get_secret_code_validated_to_send():
    """
    Generates and validates a 6-digit code.

    Returns:
        str: A validated 6-digit random code.
    """
    # Generate a random code using generate_random_code
    # Validate the code
    CODE_LENGTH = 6
    pattern = fr"^\d{{{CODE_LENGTH}}}$"  # Regular expression for exactly 6 digits
    code = input("Please enter the secret code:")
    while not re.fullmatch(pattern, code):
        print("Code is invalid (not long enough/too long)")
        code = input("Enter code again")
    return code


# class ConnectReqeust(Request):
#     def run(self):
#         print("INITIATING CONNECT REQUEST")
#
#         phone_number = get_validated_phone_number()
#         secret_code = get_secret_code_validated_to_send()
#
#         try:
#             message_dict = {
#                 "code": ProtocolCodes.init_ConnectionCode.value,
#                 "phone_number": phone_number,
#                 "secret_code" : secret_code
#             }
#             send_dict_as_json_through_established_socket_connection(conn=self.conn, data=message_dict)
#             print("USER SENT SERVER HIS CONNECT REQUEST")
#
#             data_dict_received_back = receive_json_as_dict_through_established_connection(conn=self.conn)
#
#             if data_dict_received_back["code"] != ServerSideProtocolCodes.CONNECT_REQUEST_ACCEPTED.value or ServerSideProtocolCodes.CONNECT_REQUEST_NOT_ACCEPTED.value:
#                 raise ValueError("Code Replied with (FOR CONNECT REQUEST) is INVALID")
#
#             if  data_dict_received_back["code"] == ServerSideProtocolCodes.CONNECT_REQUEST_NOT_ACCEPTED.value:
#                 print("ConnectRequestFailed")
#                 return False
#
#             return True
#
#         except OSError as error:
#             print(f"Error in RegisterRequest {error}")
#             self.send_general_client_error()

class CommunicationRequest(Request):
    def __init__(self, user, target_phone_number, message: str, server_ip=SERVER_IP, server_port=SERVER_DEFUALT_PORT):
        super().__init__(server_ip, server_port)
        self.user = user
        self.target_phone_number = target_phone_number
        self.message = message

    def run(self):
        try:
            print("INITIATING COMMUNICATION REQUEST")

            message_dict = {
                "code": ProtocolCodes.initCommunicationCode.value,
                "phone_number": self.target_phone_number,
                "sender_phone_number" : self.user.get_phone_number()
            }
            send_dict_as_json_through_established_socket_connection(conn=self.conn, data=message_dict)
            print("USER SENT SERVER HIS COMMUNICATION REQUEST")
            dict_received = receive_json_as_dict_through_established_connection(conn=self.conn)
            print("USER received RESPONSE  :", dict_received)

            if dict_received["code"] == ServerSideProtocolCodes.INVALID_PHONE_NUMBER.value:
                raise ValueError("Target phone number or/and sender's phone number sent to server is invalid")
            elif dict_received["code"] == ProtocolCodes.initConnectionAESExchange.value:
                print("Entering connection aes exchange")
                target_public_key = dict_received["public_key"]
                shared_secret = create_shared_secret(receiver_public_key=target_public_key,
                                                     sender_private_key=self.user.get_private_key())
                salt = generate_salt()
                kdf_wrapped_shared_secret = kdf_wrapper(shared_secret, salt=salt)

                aes_key = generate_aes_key()
                iv = generate_random_iv()
                wrapped_aes_key = wrap_cbc_aes_key(aes_key=aes_key, kdf_wrapped_shared_secret=kdf_wrapped_shared_secret)
                encrypted_message = encrypt_message_with_aes_cbc_key(message=self.message.encode(), aes_key=aes_key,iv=iv)

                message_dict = {"code": UserSideRequestCodes.SEND_MESSAGE.value,
                                "wrapped_aes_key": wrapped_aes_key,
                                "encrypted_message": encrypted_message
                                }

                # TODO:::::: CONTINUE
            else:
                return

        except OSError as error:
            print(f"Error in RegisterRequest {error}")
            self.send_general_client_error()
