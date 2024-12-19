from abc import ABC, abstractmethod

# Abstract Class: Protocol
class Protocol(ABC):
    def __init__(self, server=None, conn=None, database=None):
        self.json = None  # Placeholder for JSON handling logic
        self.server = server  # IP and port information
        self.conn = conn  # Connection object (e.g., socket)
        self.database = database  # Placeholder for database access

    @abstractmethod
    def protocol(self):
        """Abstract method that must be implemented by derived classes."""
        pass


# RegisterRequestProtocol Class
class RegisterRequestProtocol(Protocol):
    def protocol(self):
        """Implementation of the protocol method."""
        print("Executing RegisterRequestProtocol protocol.")

    def process_register_request(self):
        """Process the register request logic."""
        print("Processing register request...")


# ConnectRequestProtocol Class
class ConnectRequestProtocol(Protocol):
    def protocol(self):
        """Implementation of the protocol method."""
        print("Executing ConnectRequestProtocol protocol.")

    def process_connect_request(self):
        """Process the connect request logic."""
        print("Processing connect request...")


# CheckWaitingMessagesProtocol Class
class CheckWaitingMessagesProtocol(Protocol):
    def protocol(self):
        """Implementation of the protocol method."""
        print("Executing CheckWaitingMessagesProtocol protocol.")

    def process_check_user_waiting_messages(self):
        """Process the logic to check user waiting messages."""
        print("Processing check for user waiting messages...")


# ProcessCommunicateProtocol Class
class ProcessCommunicateProtocol(Protocol):
    def protocol(self):
        """Implementation of the protocol method."""
        print("Executing ProcessCommunicateProtocol protocol.")

    def process_communicate(self):
        """Process the communication logic."""
        print("Processing communication...")
