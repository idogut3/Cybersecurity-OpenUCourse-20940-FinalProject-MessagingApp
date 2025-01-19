import json
import os
import socket
import threading

import server_side.Protocols
from CommunicationCodes import ProtocolCodes
from CommunicationConstants import SERVER_DEFUALT_PORT, SERVER_IP
from CommunicationUtils import receive_json_as_dict_through_established_connection
from DataBase import DataBase
from GlobalCryptoUtils import generate_ecc_keys
from KeyLoaders import save_keys_to_files, load_public_key_from_file
from server_side.Protocols import Protocol

PROTOCOL_MAP = {
    ProtocolCodes.init_RegistrationCode.value: server_side.Protocols.RegisterRequestProtocol,
    ProtocolCodes.initConnectionAESExchange.value: server_side.Protocols.ConnectRequestProtocol
}

class Server:
    def __init__(self, host_ip: str = SERVER_IP, port: int = SERVER_DEFUALT_PORT):
        self.port = port
        self.host_ip = host_ip
        self.ADDR = (self.host_ip, self.port)
        self.database = DataBase()
        self.database_lock = threading.Lock()  # Lock for database access
        self.version = 3
        self.ECC_KEYS_FILE_PATH = 'Cybersecurity-OpenUCourse-20940-FinalProject-MessagingApp\\server_side\\SERVER_ECC_KEYS'

    def get_database(self) -> DataBase:
        with self.database_lock:  # Acquire lock for safe database access
            return self.database

    def get_version(self):
        return self.version

    def get_public_key(self):
        file_path = self.ECC_KEYS_FILE_PATH + "\\" + "public_key.pem"
        try:
            return load_public_key_from_file(file_path)
        except KeyError as error:
            raise KeyError(f"Failed to get public key, error {error}")

    def get_private_key(self):
        file_path = self.ECC_KEYS_FILE_PATH + "\\" + "private_key.pem"
        try:
            return load_public_key_from_file(file_path)
        except KeyError as error:
            raise KeyError(f"Failed to get private key, error {error}")

    # ---------------------------
    # 4. A Factory Function to Get the Correct Protocol || todo: not sure if that could be called as a factory function but idk ~idogut3
    # ---------------------------
    def get_protocol(self, conn: socket.socket, code: str, request_json) -> Protocol:
        """
        Returns an instance of the appropriate protocol class based on the code.
        """
        protocol_class = PROTOCOL_MAP.get(code)
        if protocol_class:
            return protocol_class(server=self, conn=conn, request_dict=request_json)
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
                data_dict = receive_json_as_dict_through_established_connection(conn=conn)

                # Extract the "code" from the JSON, then create and execute the correct protocol
                protocol_code = data_dict.get("code")
                if protocol_code:
                    try:
                        protocol_instance = self.get_protocol(conn=conn, code=protocol_code, request_json=data_dict)
                        # Execute the protocol logic
                        protocol_instance.run()

                    except ValueError as error:
                        print(f"Protocol instance run failed: {error}")
                        # error_response = json.dumps({"status": "error", "message": str(error)}).encode('utf-8')
                        # conn.sendall(error_response)
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
        try:
            # Create a socket to listen for incoming connections
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
                server_socket.bind((self.host_ip, self.port))  # Bind to the specified IP and port
                server_socket.listen()  # Listen for incoming connections
                print(f"Server is listening on {self.host_ip}:{self.port}...")
                # Generate keys
                public_key, private_key = generate_ecc_keys()

                # Save keys to files
                save_keys_to_files(ecc_keys_file_path=self.ECC_KEYS_FILE_PATH,
                                   public_key=public_key,
                                   private_key=private_key
                                   )
                # with open(os.path.join(self.ECC_KEYS_FILE_PATH, "private_key.pem")) as file:
                #     print(file.read())
                while True:  # Keep the server running
                    conn, addr = server_socket.accept()  # Accept a connection
                    # Start a new thread to handle the client
                    client_thread = threading.Thread(target=self.handle_client, args=(conn, addr))
                    client_thread.start()
                    print(f"Started thread {client_thread.name} to handle client {addr}")
        except OSError as error:
            print(f"Error in server run:\n{error}")
