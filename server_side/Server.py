import json
import socket
import threading
from DataBase import DataBase
from server_side.Protocols import RegisterRequestProtocol, CheckWaitingMessagesProtocol, ProcessCommunicateProtocol, \
    ConnectRequestProtocol, Protocol
from server_side.crypto_utils import generate_rsa_keys, save_keys_to_files
from server_side.utils import ProtocolsCodes

DEFAULT_PORT = 1256


class Server:
    def __init__(self, host_ip: str, port: int = DEFAULT_PORT):
        self.port = port
        self.host_ip = host_ip
        self.ADDR = (self.host_ip, self.port)
        self.database = DataBase()
        self.database_lock = threading.Lock()  # Lock for database access
        self.version = 3

    def get_database(self) -> DataBase:
        with self.database_lock:  # Acquire lock for safe database access
            return self.database

    def get_version(self):
        return self.version

    # ---------------------------
    # 4. A Factory Function to Get the Correct Protocol || todo: not sure if that could be called as a factory function but idk ~idogut3
    # ---------------------------
    def get_protocol(self, conn: socket.socket, code: str, request_json) -> Protocol:
        """
        Returns an instance of the appropriate protocol class based on the code.
        """
        if code == ProtocolsCodes.RegisterRequestProtocolCode.value:
            return RegisterRequestProtocol(server=self, conn=conn, request_json=request_json)
        elif code == ProtocolsCodes.ConnectRequestProtocolCode.value:
            return ConnectRequestProtocol(server=self, conn=conn, request_json=request_json)
        elif code == ProtocolsCodes.CheckWaitingMessagesProtocolCode.value:
            return CheckWaitingMessagesProtocol(server=self, conn=conn, request_json=request_json)
        elif code == ProtocolsCodes.ProcessCommunicateProtocolCode.value:
            return ProcessCommunicateProtocol(server=self, conn=conn, request_json=request_json)
        else:
            # You could raise an exception or return a "no-op" protocol here
            raise ValueError(f"Unknown protocol code: {code}")

    def handle_client(self, conn: socket.socket, client_addr):
        """
        Handles communication with a single client.

        Args:
            conn (socket): The socket connection object.
            client_addr (tuple): The address of the connected client.
        """
        print(f"Connection established with {client_addr}")
        try:
            while True:
                data = conn.recv(1024)  # Receive data (buffer size: 1024 bytes)
                if not data:
                    break  # Connection closed by the client

                # Decode the received data
                json_data = json.loads(data.decode('utf-8'))
                print(f"Received JSON data from {client_addr}:", json_data)

                # Extract the "code" from the JSON, then create and execute the correct protocol
                protocol_code = json_data.get("code")
                if protocol_code:
                    try:
                        protocol_instance = self.get_protocol(conn=conn, code=protocol_code, request_json=json_data)
                        # Execute the protocol logic
                        protocol_instance.run()

                    except ValueError as error:
                        print(f"Protocol instance run failed: {error}")
                        error_response = json.dumps({"status": "error", "message": str(error)}).encode('utf-8')
                        conn.sendall(error_response)
                else:
                    # If "code" is not provided, send an error or handle as needed
                    error_response = json.dumps({
                        "status": "error",
                        "message": "No code provided in JSON data"
                    }).encode('utf-8')
                    conn.sendall(error_response)

        except Exception as error:
            print(f"Error handling client {client_addr}: {error}")
        finally:
            print(f"Connection closed with {client_addr}")
            conn.close()  # Close the connection

    # def handle_connection(self, conn): todo: Not sure if this is needed or not yet ~ idogut3
    #     pass

    def run(self):
        """
        Starts a persistent multithreaded server that listens for JSON data.
        """
        # Create a socket to listen for incoming connections
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.bind((self.host_ip, self.port))  # Bind to the specified IP and port
            server_socket.listen()  # Listen for incoming connections
            print(f"Server is listening on {self.host_ip}:{self.port}...")
            # Generate keys
            private_key, public_key = generate_rsa_keys()

            # Save keys to files
            save_keys_to_files(private_key, public_key)

            while True:  # Keep the server running
                conn, addr = server_socket.accept()  # Accept a connection
                # Start a new thread to handle the client
                client_thread = threading.Thread(target=self.handle_client, args=(conn, addr))
                client_thread.start()
                print(f"Started thread {client_thread.name} to handle client {addr}")
