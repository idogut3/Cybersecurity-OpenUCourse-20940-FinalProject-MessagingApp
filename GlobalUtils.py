import json
import socket

def send_json(ip, port, data): #TODO: PROBABLY WRONG NEED TO FIX ~idogut3
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
        return response
