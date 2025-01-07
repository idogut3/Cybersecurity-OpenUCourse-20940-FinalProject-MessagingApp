import socket
import json

from GlobalConstants import SERVER_IP, SERVER_PORT
from User import User
from user_utils import *
from validations import *
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


def connect_to_server():
    """Connect the user to the server."""
    secret_code = get_secret_code()
    try:
        phone_number = read_phone_number()
        print(f"Phone number read from file: {phone_number}")
        user = User(3, load_public_key("public_key.pem"), load_private_key("private_key.pem"), phone_number)
        data_to_send = {
            "code": "Love",
            "phone_number": phone_number,
            "secret_code": secret_code
        }

        recived_data = send_json(SERVER_IP, SERVER_PORT, data_to_send)
        if recived_data["code"] == "We":
            print("connection established!")
            user.is_connected_to_server = True


    except (FileNotFoundError, ValueError) as e:
        print(f"Error: {e}")


def get_secret_code() -> str:
    """
    Prompt the user to enter a 6-digit secret code and validate it.

    Returns:
        str: The validated 6-digit secret code.
    """
    while True:
        # Prompt the user for input
        code = input("Enter a 6-digit secret code: ").strip()

        # Check if the code is 6 digits long and numeric
        if code.isdigit() and len(code) == 6:
            print("Code validated successfully.")
            return code
        else:
            print("Invalid code. Please enter a 6-digit numeric code.")


def display_options():
    """Display available user options (CLI-based implementation)."""
    print("1. Register to server")
    print("2. Connect to server")
    print("3. Add new connection")
    print("4. Send message")
    print("5. Show waiting messages")


def get_validated_option_number():
    """
        After the options were displayed, returns the number the user chose,
        :raises error if the option number is illegal
    """
    while True:
        try:
            # Prompt the user for input
            number = int(input("Enter a number between 1 and 5: "))

            # Validate the range
            if 1 <= number <= 5:
                return number
            else:
                print("\nInvalid input. Please enter a number between 1 and 5.")

        except ValueError:
            print("Invalid input. Please enter a valid number.")


def decide_which_process_to_perform(chosen_number):
    if chosen_number == 1:
        register_to_server()
    elif chosen_number == 2:
        connect_to_server()
    elif chosen_number == 3:
        pass  # todo
    elif chosen_number == 4:
        pass  # todo
    else:
        pass  # todo



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
