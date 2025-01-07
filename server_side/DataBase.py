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

    def get_public_key_by_phone_number(self, phone_number):
        """
        Get the public key of a user by their phone number.
        """
        if phone_number in self.users:
            return self.users[phone_number].get_public_key()
        print(f"No user found with phone number {phone_number}.")
        return None

    def check_secret_code(self, user, code):
        """
        Check if the given secret code matches the user's stored secret code.
        """
        if user in self.users.values():
            return user.secret_code == code
        print("User not found in the database.")
        return False
