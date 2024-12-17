import random
from enum import Enum
import socket
import json

class ProtocolsCodes(Enum):
    RegisterRequestProtocolCode = "We"
    ConnectRequestProtocolCode = "Love"
    CheckWaitingMessagesProtocolCode = "This"
    ProcessCommunicateProtocolCode = "Project"

def send_by_secure_channel(code):
    return 2

def generate_random_code():
    """Generate a random 6-digit code as a string, preserving leading zeros."""
    return f"{random.randint(0, 999999):06}"

def send_json(ip, port, data):
    """
    Sends JSON data to a specified IP and port.

    Args:
        ip (str): The IP address to send data to.
        port (int): The port number to send data to.
        data (dict): The JSON data to send.
    """
    json_data = json.dumps(data)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((ip, port))  # Connect to the server
        client_socket.sendall(json_data.encode('utf-8'))  # Send JSON data
        response = client_socket.recv(1024).decode('utf-8')  # Receive the server's response
        print("Server response:", response)
