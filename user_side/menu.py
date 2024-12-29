import random


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

print(generate_random_code())