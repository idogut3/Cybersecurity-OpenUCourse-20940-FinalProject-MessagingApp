import socket
import json
import threading


def handle_client(conn:socket.socket, addr):
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

            # Optional: Send a response back to the client
            response = json.dumps({"status": "success"}).encode('utf-8')
            conn.sendall(response)
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
        server_socket.listen()  # Listen for incoming connections
        print(f"Server is listening on {ip}:{port}...")

        while True:  # Keep the server running
            conn, addr = server_socket.accept()  # Accept a connection
            # Start a new thread to handle the client
            client_thread = threading.Thread(target=handle_client, args=(conn, addr))
            client_thread.start()
            print(f"Started thread {client_thread.name} to handle client {addr}")


if __name__ == "__main__":
    server_ip = "127.0.0.1"  # Bind to localhost
    server_port = 5000  # Server port
    start_server(server_ip, server_port)
