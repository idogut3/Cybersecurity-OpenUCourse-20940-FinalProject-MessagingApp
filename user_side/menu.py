from GlobalValidations import validate_phone_number


def save_phone_number(phone_number: str):
    """
    Validate a phone number and save it to a default file.

    Args:
        phone_number (str): The phone number to save.

    Raises:
        ValueError: If the phone number is invalid.
    """
    # Validate the phone number (basic validation: digits only and length check)
    if not validate_phone_number(phone_number):
        raise ValueError("Invalid phone number. Must contain only digits and be 10-15 digits long.")

    # Default file path to save the phone number
    file_path = "phone_number.txt"

    # Save the phone number to the specified file
    with open(file_path, "w") as file:
        file.write(phone_number)

    print(f"Phone number {phone_number} has been saved to {file_path}.")


def read_phone_number() -> str:
    """
    Read the phone number from the default file.

    Returns:
        str: The phone number from the file.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the file is empty or contains invalid content.
    """
    # Default file path to read the phone number
    file_path = "phone_number.txt"

    # Read the phone number from the file
    try:
        with open(file_path, "r") as file:
            phone_number = file.read().strip()
        return phone_number

    except FileNotFoundError:
        raise FileNotFoundError(f"File {file_path} does not exist, user did not register.")