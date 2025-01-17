from GlobalValidations import is_valid_phone_number
from User import User

class DataBase:
    def __init__(self):
        self.users = {}  # Dictionary to store users, keyed by phone_number

    def is_connected(self, user1, user2):
        """
        Check if user1 is explicitly connected to user2.
        """
        if user1 in self.users and user2 in self.users:
            return user2 in self.users[user1].connections
        return False

    def register_user(self, phone_number, public_key, secret_code):
        """
        Register a user with the given phone number.
        """
        self.users[phone_number] = User(phone_number, public_key, secret_code)
        return True

    def is_user_registered(self, phone_number):
        """
        Check if a user with the given phone number is registered.
        """
        return phone_number in self.users

    def get_user_by_phone_number(self, phone_number):
        if not is_valid_phone_number(phone_number=phone_number):
            raise ValueError("phone_number is invalid")
        if not self.is_user_registered(phone_number):
            raise ValueError("User is not registered for this phone number")
        return self.users[phone_number]

    def get_public_key_by_phone_number(self, phone_number):
        """
        Get the public key of a user by their phone number.
        """
        if phone_number in self.users:
            return self.users[phone_number].get_public_key()
        print(f"No user found with phone number {phone_number}.")
        return None

    def is_secret_code_correct_for_user(self, user, code):
        """
        Check if the given secret code matches the user's stored secret code.
        """
        if user in self.users.values():
            return user.secret_code == code
        print("User not found in the database.")
        return False
