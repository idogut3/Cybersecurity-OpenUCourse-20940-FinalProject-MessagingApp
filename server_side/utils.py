import random

def send_by_secure_channel(code):
    print("code through secure channel is = ", code)

def generate_random_code():
    """
    Generates a 6-digit random code by creating one digit at a time.

    Returns:
        str: A 6-digit random code as a string.
    """
    code = ""
    for _ in range(6):
        digit = random.randint(0, 9)  # Generate a random digit (0-9)
        code += str(digit)  # Append the digit to the code as a string
    return code


#
# def register_to_server(phone_number: str):
#     """Register the user to the server."""
#     # Implement the logic for server registration
#     # At the end of the logic, if got register success, save phone number.
#     try:
#         save_phone_number(phone_number)
#         user = User(3, load_public_key("public_key.pem"), load_private_key("private_key.pem"), phone_number)
#     except ValueError as e:
#         print(f"Error: {e}")
#
#
# def save_phone_number(phone_number: str):
#     """
#     Validate a phone number and save it to a default file.
#
#     Args:
#         phone_number (str): The phone number to save.
#
#     Raises:
#         ValueError: If the phone number is invalid.
#     """
#     # Validate the phone number (basic validation: digits only and length check)
#     if not validate_phone_number(phone_number):
#         raise ValueError("Invalid phone number. Must contain only digits and be 10-15 digits long.")
#
#     # Default file path to save the phone number
#     file_path = "phone_number.txt"
#
#     # Save the phone number to the specified file
#     with open(file_path, "w") as file:
#         file.write(phone_number)
#
#     print(f"Phone number {phone_number} has been saved to {file_path}.")
#
#
# def read_phone_number() -> str:
#     """
#     Read the phone number from the default file.
#
#     Returns:
#         str: The phone number from the file.
#
#     Raises:
#         FileNotFoundError: If the file does not exist.
#         ValueError: If the file is empty or contains invalid content.
#     """
#     # Default file path to read the phone number
#     file_path = "phone_number.txt"
#
#     # Read the phone number from the file
#     try:
#         with open(file_path, "r") as file:
#             phone_number = file.read().strip()
#         return phone_number
#
#     except FileNotFoundError:
#         raise FileNotFoundError(f"File {file_path} does not exist, user did not register.")
#
#
# def connect_to_server():
#     """Connect the user to the server."""
#     secret_code = get_secret_code()
#     try:
#         phone_number = read_phone_number()
#         print(f"Phone number read from file: {phone_number}")
#         user = User(3, load_public_key("public_key.pem"), load_private_key("private_key.pem"), phone_number)
#         data_to_send = {
#             "code": "We",
#             "phone_number": phone_number,
#             "secret_code": secret_code
#         }
#
#         recived_data = send_json(SERVER_IP, SERVER_PORT, data_to_send)
#         if recived_data["code"] == "We":
#             print("connection established!")
#             user.is_connected_to_server = True
#
#
#     except (FileNotFoundError, ValueError) as e:
#         print(f"Error: {e}")
#
#
# def get_secret_code() -> str:
#     """
#     Prompt the user to enter a 6-digit secret code and validate it.
#
#     Returns:
#         str: The validated 6-digit secret code.
#     """
#     while True:
#         # Prompt the user for input
#         code = input("Enter a 6-digit secret code: ").strip()
#
#         # Check if the code is 6 digits long and numeric
#         if code.isdigit() and len(code) == 6:
#             print("Code validated successfully.")
#             return code
#         else:
#             print("Invalid code. Please enter a 6-digit numeric code.")
#
#
# def display_options():
#     """Display available user options (CLI-based implementation)."""
#     print("1. Register to server")
#     print("2. Connect to server")
#     print("3. Add new connection")
#     print("4. Send message")
#     print("5. Show waiting messages")
#
#
# def get_validated_option_number():
#     """
#         After the options were displayed, returns the number the user chose,
#         :raises error if the option number is illegal
#     """
#     while True:
#         try:
#             # Prompt the user for input
#             number = int(input("Enter a number between 1 and 5: "))
#
#             # Validate the range
#             if 1 <= number <= 5:
#                 return number
#             else:
#                 print("\nInvalid input. Please enter a number between 1 and 5.")
#
#         except ValueError:
#             print("Invalid input. Please enter a valid number.")
#
#
# def decide_which_process_to_perform(chosen_number):
#     if chosen_number == 1:
#         register_to_server()
#     elif chosen_number == 2:
#         connect_to_server()
#     elif chosen_number == 3:
#         pass  # todo
#     elif chosen_number == 4:
#         pass  # todo
#     else:
#         pass  # todo
#
#

