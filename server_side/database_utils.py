import re

def validate_phone_number(phone_number: str) -> bool:
    """
    Validates that the phone number is a 9-digit number formatted as +9725XXXXX.

    Args:
        phone_number (str): The phone number to validate.

    Returns:
        bool: True if valid, False otherwise.
    """
    # Regular expression for validating phone numbers in the format +9725XXXXX
    pattern = r"^\+9725\d{6}$"
    return re.match(pattern, phone_number) is not None
