import socket
import json

from GlobalConstants import SERVER_IP, SERVER_PORT
from User import User
from user_side.menu import display_options, get_validated_option_number, decide_which_process_to_perform
from user_utils import *
from pycparser.c_ast import Switch



# def register_to_server(phone_number: str): # TODO: NOT SUPPOSED TO BE HERE
#     """Register the user to the server."""
#     # Implement the logic for server registration
#     data_to_send = {
#         "code": "We"
#     }
#
#     recived_data = send_json(SERVER_IP, SERVER_PORT, data_to_send) # the server should send a json with the same code and his public key.
#
#     response_dict = json.loads(recived_data)
#     # Access fields
#     print("code:", response_dict.get("code"))
#     print("public_key:", response_dict.get("public_key"))
#     if response_dict.get("code") != "We":
#         #there is a problem
#         return 1
#     data_to_send = {
#         "code": "We",
#         "phone_number": encrypt_message(phone_number, response_dict.get("public_key"))
#     }
#
#     recived_data = send_json(SERVER_IP, SERVER_PORT, data_to_send) # the server should send a json with the same code and his public key.
#
#     response_dict = json.loads(recived_data)
#
#     # At the end of the logic, if got register success, save phone number.
#     try:
#         save_phone_number(phone_number)
#         user = User(3, load_public_key("public_key.pem"), load_private_key("private_key.pem"), phone_number)
#     except ValueError as e:
#         print(f"Error: {e}")

# Example usage
if __name__ == "__main__":
    while True:
        display_options()
        chosen_number = get_validated_option_number()
        decide_which_process_to_perform(chosen_number)
        data_to_send = {
            "name": "Alice",
            "age": 25,
            "email": "alice@example.com"
        }

        send_json(SERVER_IP, SERVER_PORT, data_to_send)
