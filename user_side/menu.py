from CommunicationConstants import SERVER_IP, SERVER_DEFUALT_PORT
from GlobalCryptoUtils import generate_ecc_keys
from GlobalValidations import is_valid_phone_number, is_valid_email
from user_side import User
from user_side.Requests import RegisterRequest, ConnectReqeust
from user_side.User import get_email_validated, get_validated_phone_number, connect_to_user
from user_side.user_utils import load_public_key, load_private_key


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


def display_options_after_connection():
    print("Now that you are connected what do you want to do?")
    print("1. Send message")
    print("2. Show waiting messages")


def get_validated_option_number(lowest, highest):
    """
        After the options were displayed, returns the number the user chose,
        :raises error if the option number is illegal
    """
    while True:
        try:
            # Prompt the user for input
            number = int(input("Enter a number between 1 and 3: "))

            # Validate the range
            if lowest <= number <= highest:
                return number
            else:
                print("\nInvalid input. Please enter a number between 1 and 3.")

        except ValueError:
            print("Invalid input. Please enter a valid number.")


def decide_which_process_to_perform(chosen_number):
    connected = False
    if chosen_number == 1:
        user = User.create_user()
        register_request = RegisterRequest(user=user)
        connected = register_request.run()
    elif chosen_number == 2:
        user = connect_to_user()
        connect_request = ConnectReqeust(user=user)
        connected = connect_request.run()

    if connected:
        display_options_after_connection()
        chosen_number = get_validated_option_number(1, 2)

        # if chosen_number == 1: TODO::::::::::::::::::::::::::
        #     send_message_request =
        # elif chosen_number == 2:






