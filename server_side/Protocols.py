import base64
import socket
from abc import ABC, abstractmethod

from CommunicationCodes import GeneralCodes, UserSideRequestCodes, ServerSideProtocolCodes, ProtocolCodes
from CommunicationUtils import send_dict_as_json_through_established_socket_connection, \
    receive_json_as_dict_through_established_connection
from GlobalCryptoUtils import create_shared_secret, kdf_wrapper, unwrap_cbc_aes_key, decrypt_message_with_aes_cbc_key
from GlobalValidations import is_valid_phone_number
from KeyLoaders import serialize_public_ecc_key_to_pem_format, deserialize_pem_to_ecc_public_key, clean_key_string
from Message import Message
from server_side.utils import send_by_secure_channel
from user_side.user_utils import generate_random_code, load_public_key, load_public_key_from_data


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

    def send_invalid_phone_number(self, error_description="Invalid phone number error"):
        print(f"PHONE NUMBER WAS INVALID error: {error_description}")
        message_dict = {
            "code": ServerSideProtocolCodes.INVALID_PHONE_NUMBER.value,
            "error_description": error_description
        }
        send_dict_as_json_through_established_socket_connection(conn=self.conn, data=message_dict)

    def send_invalid_secret_code(self):
        message_dict = {
            "code": ServerSideProtocolCodes.INVALID_SECRET_CODE.value
        }
        send_dict_as_json_through_established_socket_connection(conn=self.conn, data=message_dict)


class RegisterRequestProtocol(Protocol):
    def run(self):
        print("Executing RegisterRequestProtocol protocol")
        error_message = "General Server Error"
        try:
            server_public_key = self.server.get_public_key()
            # server_private_key = self.server.get_private_key()

            self.send_public_key_to_user(server_public_key)
            print("SERVER SENT USER PUBLIC KEY")

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

            request_dict = receive_json_as_dict_through_established_connection(self.conn)

            print("RESPONSE GOTTEN IS :", request_dict)
            if request_dict["code"] == ProtocolCodes.init_CheckWaitingMessagesCode.value:
                protocol_instance = CheckWaitingMessagesProtocol(server=self.server,
                                                                 conn=self.conn,
                                                                 request_dict=request_dict,
                                                                 user_phone_number=phone_number)
                protocol_instance.run()
            elif request_dict["code"] == ProtocolCodes.initCommunicationCode.value:
                protocol_instance = ProcessCommunicateProtocol(server=self.server,
                                                               conn=self.conn,
                                                               request_dict=request_dict,
                                                              senders_phone_number=phone_number)
                protocol_instance.run()
            else:
                return

        except OSError:
            print("Error in RegisterRequestProtocol")
            self.send_general_server_error(error_message)
            return

    def send_public_key_to_user(self, public_key):
        message_dict = {
            "code": ServerSideProtocolCodes.SEND_PUBLIC_KEY.value,
            "public_key": serialize_public_ecc_key_to_pem_format(public_key).decode('utf-8')
        }
        send_dict_as_json_through_established_socket_connection(conn=self.conn, data=message_dict)


class ConnectRequestProtocol(Protocol):
    def run(self):
        print("Executing ConnectRequestProtocol protocol.")
        try:
            phone_number_received = self.request_dict["phone_number"]
            wrapped_aes_key = base64.b64decode(self.request_dict["wrapped_aes_key"])
            iv_for_wrapped_key = base64.b64decode(self.request_dict["iv_for_wrapped_key"])
            encrypted_secret_code = base64.b64decode(self.request_dict["encrypted_secret_code"])
            iv_for_secret = base64.b64decode(self.request_dict["iv_for_secret"])
            received_salt = base64.b64decode(self.request_dict["salt"])

            print("REQUEST DICT IS:", self.request_dict)

            if not is_valid_phone_number(phone_number_received) or not self.database.is_user_registered(
                    phone_number=phone_number_received):
                self.send_invalid_phone_number()
                return False
            user_public_key_bytes = clean_key_string(
                self.database.get_public_key_by_phone_number(phone_number=phone_number_received))

            # print(f"user_public_key_bytes type: {type(user_public_key_bytes)}")
            # print(f"user_public_key_bytes:\n\n\n {user_public_key_bytes}")
            user_public_key_ecc_key = load_public_key_from_data(user_public_key_bytes)
            server_private_key = self.server.get_private_key()

            #print(f"USER PUBLIC KEY TYPE {type(user_public_key_ecc_key)}")
            #print(f"USER PUBLIC KEY IS:\n {user_public_key_ecc_key}")

            #print(f"SERVER PRIVATE KEY TYPE {type(server_private_key)}")
            #print(f"SERVER PRIVATE KEY IS:\n {server_private_key}")

            # Reconstruct the derived AES key using the same shared secret and salt
            shared_secret = create_shared_secret(user_public_key_ecc_key, server_private_key)
            reconstructed_encrypted_aes_key = kdf_wrapper(shared_secret, received_salt)

            decrypted_aes_key = unwrap_cbc_aes_key(wrapped_aes_key=wrapped_aes_key,
                                                   kdf_wrapped_shared_secret=reconstructed_encrypted_aes_key,
                                                   iv=iv_for_wrapped_key)

            decrypted_secret_code = decrypt_message_with_aes_cbc_key(encrypted_message=encrypted_secret_code,
                                                                     aes_key=decrypted_aes_key,
                                                                     iv=iv_for_secret).decode("utf-8")

            user = self.database.get_user_by_phone_number(phone_number=phone_number_received)
            if not self.database.is_secret_code_correct_for_user(user=user, code=decrypted_secret_code):
                print(f"INVALID CODE GOT: {decrypted_secret_code}")
                self.send_invalid_secret_code()
                return

            self.send_connect_request_approved()
            print("CONNECT REQUEST APPROVED USER")

            request_dict = receive_json_as_dict_through_established_connection(self.conn)

            if request_dict["code"] == ProtocolCodes.init_CheckWaitingMessagesCode.value:
                protocol_instance = CheckWaitingMessagesProtocol(server=self.server,
                                                                 conn=self.conn,
                                                                 request_dict=request_dict,
                                                                 user_phone_number=phone_number_received)
                protocol_instance.run()
            elif request_dict["code"] == ProtocolCodes.initCommunicationCode.value:
                protocol_instance = ProcessCommunicateProtocol(server=self.server,
                                                               conn=self.conn,
                                                               request_dict=request_dict,
                                                               senders_phone_number=phone_number_received)
                protocol_instance.run()
            else:
                return

        except OSError as error:
            print(f"Error at ConnectRequestProtocol {error}")
            self.send_general_server_error()

    def send_connect_request_approved(self):
        message_dict = {
            "code": ServerSideProtocolCodes.CONNECT_REQUEST_ACCEPTED.value
        }
        send_dict_as_json_through_established_socket_connection(conn=self.conn, data=message_dict)


class CheckWaitingMessagesProtocol(Protocol):
    def __init__(self, server, conn: socket.socket, request_dict: dict, user_phone_number: str):
        super().__init__(server=server, conn=conn, request_dict=request_dict)
        self.user_phone_number = user_phone_number

    def run(self):
        print("Executing CheckWaitingMessagesProtocol protocol.")
        try:
            waiting_messages = self.database.get_waiting_messages_for_user(phone_number=self.user_phone_number)

            print("SERVER SENDING MESSAGES TO USER")
            self.send_waiting_messages(waiting_messages=waiting_messages)
            print("SERVER SENT USER ALL MESSAGES")
            self.database.clear_messages_for_user(phone_number=self.user_phone_number)
            print("SERVER CLEARED MESSAGES FOR USER")
        except OSError as error:
            print(f"Error at CheckWaitingMessagesProtocol {error}")
            self.send_general_server_error()

    def send_waiting_messages(self, waiting_messages: list):
        """
        Sends each waiting message to the user over the established connection.

        Args:
            waiting_messages (list): A list of messages to send to the user.
        """
        total_messages = len(waiting_messages)  # Get the total number of messages
        if total_messages == 0:
            message_json_to_send = {"code": ServerSideProtocolCodes.CHECK_WAITING_MESSAGES_APPROVED.value,
                                    "remaining_messages": 0
                                    }
            send_dict_as_json_through_established_socket_connection(conn=self.conn, data=message_json_to_send)
            return  # No messages to send

        message_index = 0  # Initialize an index for the loop
        for message in waiting_messages:
            remaining_messages = total_messages - message_index # Calculate remaining messages
            message_public_key_pem = serialize_public_ecc_key_to_pem_format(message.get_senders_public_key())

            message_json_to_send = {"code": ServerSideProtocolCodes.CHECK_WAITING_MESSAGES_APPROVED.value,
                                    "senders_phone_number": message.get_senders_phone_number(),
                                    "senders_public_key": base64.b64encode(message_public_key_pem).decode('utf-8'),
                                    "wrapped_aes_key":  base64.b64encode(message.get_wrapped_aes_key()).decode('utf-8'),
                                    "iv_for_wrapped_key":  base64.b64encode(message.get_iv_for_wrapped_key()).decode('utf-8'),
                                    "encrypted_message":  base64.b64encode(message.get_encrypted_message()).decode('utf-8'),
                                    "iv_for_message":  base64.b64encode(message.get_iv_for_message()).decode('utf-8'),
                                    "salt":  base64.b64encode(message.get_salt()).decode('utf-8'),
                                    "remaining_messages": remaining_messages
                                    }
            send_dict_as_json_through_established_socket_connection(conn=self.conn, data=message_json_to_send)
            message_index += 1


class ProcessCommunicateProtocol(Protocol):
    def __init__(self, server, conn: socket.socket, request_dict: dict, senders_phone_number: str):
        super().__init__(server=server, conn=conn, request_dict=request_dict)
        self.senders_phone_number = senders_phone_number

    def run(self):
        """Implementation of the protocol method."""
        print("Executing ProcessCommunicateProtocol protocol.")
        try:
            recipients_phone_number = self.request_dict["recipients_phone_number"]
            sender_phone_number = self.senders_phone_number

            if not is_valid_phone_number(recipients_phone_number) or not is_valid_phone_number(sender_phone_number):
                self.send_invalid_phone_number(error_description="Phone number is invalid for recipient or sender's")
                return

            elif not self.database.is_user_registered(recipients_phone_number) or not self.database.is_user_registered(
                    sender_phone_number):
                self.send_invalid_phone_number(
                    error_description="Phone number for recipient or sender's not registered to server")
                return

            print("APPROVED ProcessCommunicate SENDING USER JSON TO TELL HIM HE CAN SEND A MESSAGE")
            recipients_public_key_raw = self.database.get_public_key_by_phone_number(phone_number=recipients_phone_number)
            print(f"THE  recipients_public_key_raw is {recipients_public_key_raw} and his type {type(recipients_public_key_raw)}")

            self.send_encrypted_message_approved(recipients_public_key=recipients_public_key_raw)

            request_dict = receive_json_as_dict_through_established_connection(self.conn)

            print("SERVER received RESPONSE  :", request_dict)

            if request_dict["code"] != UserSideRequestCodes.SEND_MESSAGE.value:
                raise ValueError("GOT UNEXPECTED USER MESSAGE CODE, EXISTING")

            sender_public_key_pem = base64.b64decode(request_dict["sender_public_key"])
            sender_public_key = deserialize_pem_to_ecc_public_key(sender_public_key_pem)
            print(f"sender_public_key {sender_public_key}, and his type is {type(sender_public_key)}")
            wrapped_aes_key =  base64.b64decode(request_dict["wrapped_aes_key"])
            iv_for_wrapped_key =  base64.b64decode(request_dict["iv_for_wrapped_key"])
            encrypted_message =  base64.b64decode(request_dict["encrypted_message"])
            iv_for_message =  base64.b64decode(request_dict["iv_for_message"])
            salt =  base64.b64decode(request_dict["salt"])

            message = Message(senders_phone_number=sender_phone_number, senders_public_key=sender_public_key,
                              wrapped_aes_key=wrapped_aes_key, iv_for_wrapped_key=iv_for_wrapped_key,
                              encrypted_message=encrypted_message, iv_for_message=iv_for_message, salt=salt)

            self.database.add_message_to_user(phone_number=recipients_phone_number, message=message)

            print("ADDED MESSAGE TO USER")

        except OSError as error:
            print(f"Error at ProcessCommunicateProtocol {error}")
            self.send_general_server_error()

    def send_encrypted_message_approved(self, recipients_public_key):
        message_dict = {"code": ServerSideProtocolCodes.SEND_YOUR_ENCRYPTED_MESSAGE.value,
                        "public_key":  recipients_public_key
                        }
        print(f"THE ENCRYPTED MESSAGE APPROVED WE SEND IS THIS:::: {message_dict}")
        send_dict_as_json_through_established_socket_connection(conn=self.conn, data=message_dict)
