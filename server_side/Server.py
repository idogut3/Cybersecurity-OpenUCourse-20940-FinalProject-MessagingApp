import socket
import threading

from DataBase import DataBase


class Server:
    def __init__(self, host):
        DEFAULT_PORT = int("1256")
        port = DEFAULT_PORT
        try:
            port_info_file = open("port.info", "r")
            # assuming the port_info_file is correct in its form
            port = int(port_info_file.read())
        except OSError as error:
            print("Error: Error accessing port.info file")
            print(error)
            print("using default port: ", DEFAULT_PORT)
        finally:
            self.port = port
            self.host = host
            self.ADDR = (self.host, self.port)
            self.database = DataBase()
            self.database_lock = threading.Lock()  # Lock for database access
            self.version = 3

    def get_database(self) -> DataBase:
        with self.database_lock:  # Acquire lock for safe database access
            return self.database

    def get_version(self):
        return self.version

    def check_existing_database(self):  # Question 3
        pass

    def handle_client(self, conn, addr):
        print("Connected by:", addr)
        try:
            self.handle_connection(conn)
        finally:
            conn.close()  # Ensure the connection is closed properly

    def handle_connection(self, conn):
        pass

    def run(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(self.ADDR)
            s.listen()
            print(f"Server listening on {self.ADDR}")
            while True:
                conn, addr = s.accept()
                client_thread = threading.Thread(target=self.handle_client, args=(conn, addr))
                client_thread.start()