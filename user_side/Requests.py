import socket
import time
from abc import ABC, abstractmethod

from CommunicationCodes import ProcessCodes, SubProcessCodes
from CommunicationConstants import SERVER_IP, SERVER_DEFUALT_PORT
from CommunicationUtils import send_dict_as_json_through_established_socket_connection, \
    receive_json_as_dict_through_established_connection
from user_side.User import User
from user_side.menu import read_phone_number


class Request(ABC):
    def __init__(self, server_ip: SERVER_IP, server_port: SERVER_DEFUALT_PORT, user:User):
        self.server_ip = server_ip
        self.server_port = server_port
        self.user = User
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
        message_dict = {"code": SubProcessCodes.GeneralCodes.GENERAL_CLIENT_ERROR.value,
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
    def run(self):
        try:
            message_dict = {
                "code": ProcessCodes.init_RegistrationCode.value
            }
            send_dict_as_json_through_established_socket_connection(conn=self.conn, data=message_dict)
            dict_received = receive_json_as_dict_through_established_connection(conn=self.conn)

            if dict_received["code"] != SubProcessCodes.ServerSideProtocolCodes.Registration.SEND_PUBLIC_KEY.value:
                raise ValueError("Wrong code received, was suppose to receive Registration.SEND_PUBLIC_KEY")
            if not "public_key" in dict_received:
                raise ValueError("No public_key value in dict received in Registration.SEND_PUBLIC_KEY")

            server_public_key = dict_received["public_key"]
            phone_number = read_phone_number()

            self.send_phone_number(phone_number=phone_number)

            ask_user_if_received_secret_code()



        except OSError as error:
            print(f"Error in RegisterRequest {error}")
            self.send_general_client_error()

    def send_phone_number(self, phone_number):
        message_dict = {"code": SubProcessCodes.UserSideRequestCodes.Registration.SEND_PHONE_NUMBER.value,
                        "phone_number": phone_number}
        send_dict_as_json_through_established_socket_connection(conn=self.conn, data=message_dict)

    def send_public_key(self):
        pass


