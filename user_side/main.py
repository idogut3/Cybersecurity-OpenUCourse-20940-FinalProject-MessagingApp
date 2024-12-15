import socket
import json

from pycparser.c_ast import Switch


def send_json(ip, port, data):
    """
    Sends JSON data to a specified IP and port.

    Args:
        ip (str): The IP address to send data to.
        port (int): The port number to send data to.
        data (dict): The JSON data to send.
    """
    # Convert the dictionary to a JSON string
    json_data = json.dumps(data)

    # Create a socket connection
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((ip, port))  # Connect to the server
        client_socket.sendall(json_data.encode('utf-8'))  # Send JSON data

        # Receive the server's response
        response = client_socket.recv(1024).decode('utf-8')
        print("Server response:", response)


def register_to_server():
    """Register the user to the server."""
    pass  # Implement the logic for server registration

def connect_to_server():
    """Connect the user to the server."""
    pass  # Implement the logic for server connection


def display_options():
    """Display available user options (CLI-based implementation)."""
    print("1. Register to server")
    print("2. Connect to server")
    print("3. Add new connection")
    print("4. Send message")
    print("5. Show waiting messages")

def get_number_input():
    """
    Prompts the user to input a number between 1 and 5.

    Returns:
        int: A valid number between 1 and 5.
    """
    while True:
        try:
            # Prompt the user for input
            number = int(input("Enter a number between 1 and 5: "))

            # Validate the range
            if 1 <= number <= 5:
                return number
            else:
                print("Invalid input. Please enter a number between 1 and 5.")
        except ValueError:
            print("Invalid input. Please enter a valid number.")


def decide_which_process_to_perform(chosen_number):
    if chosen_number == 1:
        register_to_server()
    elif chosen_number == 2:
        connect_to_server()
    elif chosen_number == 3:
        pass#todo
    elif chosen_number == 4:
        pass#todo
    else:
        pass#todo



# Example usage
if __name__ == "__main__":
    server_ip = "127.0.0.1"  # Server IP
    server_port = 5000       # Server port
    while(True):
        display_options()
        chosen_number = get_number_input()
        decide_which_process_to_perform(chosen_number)
        data_to_send = {
            "name": "Alice",
            "age": 25,
            "email": "alice@example.com"
        }

        send_json(server_ip, server_port, data_to_send)
