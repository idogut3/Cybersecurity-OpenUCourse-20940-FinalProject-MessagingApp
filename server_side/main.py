import socket
import json
import threading

from server_side.Protocols import RegisterRequestProtocol, ConnectRequestProtocol, CheckWaitingMessagesProtocol, \
    ProcessCommunicateProtocol, Protocol
from server_side.crypto_utils import generate_rsa_keys, save_keys_to_files
from server_side.utils import ProtocolsCodes


# ---------------------------
# 4. A Factory Function to Get the Correct Protocol
# ---------------------------
def get_protocol_by_code(code: str, conn: socket.socket, addr, database=None) -> Protocol:
    """
    Returns an instance of the appropriate protocol class based on the code.
    """
    if code == ProtocolsCodes.RegisterRequestProtocolCode.value:
        return RegisterRequestProtocol(server=addr, conn=conn, database=database)
    elif code == ProtocolsCodes.ConnectRequestProtocolCode.value:
        return ConnectRequestProtocol(server=addr, conn=conn, database=database)
    elif code == ProtocolsCodes.CheckWaitingMessagesProtocolCode.value:
        return CheckWaitingMessagesProtocol(server=addr, conn=conn, database=database)
    elif code == ProtocolsCodes.ProcessCommunicateProtocolCode.value:
        return ProcessCommunicateProtocol(server=addr, conn=conn, database=database)
    else:
        # You could raise an exception or return a "no-op" protocol here
        raise ValueError(f"Unknown protocol code: {code}")


def handle_client(conn: socket.socket, addr):
    """
    Handles communication with a single client.

    Args:
        conn (socket): The socket connection object.
        addr (tuple): The address of the connected client.
    """
    print(f"Connection established with {addr}")
    try:
        while True:
            data = conn.recv(1024)  # Receive data (buffer size: 1024 bytes)
            if not data:
                break  # Connection closed by the client

            # Decode the received data
            json_data = json.loads(data.decode('utf-8'))
            print(f"Received JSON data from {addr}:", json_data)

            # Extract the "code" from the JSON, then create and execute the correct protocol
            protocol_code = json_data.get("code")
            if protocol_code:
                try:
                    protocol_instance = get_protocol_by_code(protocol_code, conn, addr)
                    protocol_instance.json = json_data  # If you want to store the data
                    # Execute the protocol logic
                    protocol_instance.protocol()

                except ValueError as e:
                    print(f"Error: {e}")
                    error_response = json.dumps({"status": "error", "message": str(e)}).encode('utf-8')
                    conn.sendall(error_response)
            else:
                # If "code" is not provided, send an error or handle as needed
                error_response = json.dumps({
                    "status": "error",
                    "message": "No code provided in JSON data"
                }).encode('utf-8')
                conn.sendall(error_response)

    except Exception as e:
        print(f"Error handling client {addr}: {e}")
    finally:
        print(f"Connection closed with {addr}")
        conn.close()  # Close the connection


def start_server(ip, port):
    """
    Starts a persistent multithreaded server that listens for JSON data.

    Args:
        ip (str): The IP address to bind to.
        port (int): The port number to bind to.
    """
    # Create a socket to listen for incoming connections
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((ip, port))  # Bind to the specified IP and port
        server_socket.listen()          # Listen for incoming connections
        print(f"Server is listening on {ip}:{port}...")
        # Generate keys
        private_key, public_key = generate_rsa_keys()

        # Save keys to files
        save_keys_to_files(private_key, public_key)

        while True:  # Keep the server running
            conn, addr = server_socket.accept()  # Accept a connection
            # Start a new thread to handle the client
            client_thread = threading.Thread(target=handle_client, args=(conn, addr))
            client_thread.start()
            print(f"Started thread {client_thread.name} to handle client {addr}")


if __name__ == "__main__":
    server_ip = "127.0.0.1"  # Bind to localhost
    server_port = 5000       # Server port
    start_server(server_ip, server_port)