import re

def is_valid_phone_number(phone_number: str) -> bool:
    """
    Validates that the phone number is a 9-digit number formatted as +9725XXXXX.

    Args:
        phone_number (str): The phone number to validate.

    Returns:
        bool: True if valid, False otherwise.
    """
    # Regular expression for validating phone numbers in the format +9725XXXXX
    pattern = r"^\+9725\d{8}$"
    return re.match(pattern, phone_number) is not None


def is_valid_email(email: str) -> bool:
    """
    Validates if the provided email is in a correct format.

    Args:
        email (str): The email to validate.

    Returns:
        bool: True if the email is valid, False otherwise.
    """
    # Regular expression for basic email validation
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'

    # Using re.match to check if the email matches the pattern
    if re.match(email_regex, email):
        return True
    else:
        return False