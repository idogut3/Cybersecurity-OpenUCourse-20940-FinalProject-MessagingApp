import json
import socket

from CommunicationConstants import JSON_LENGTH_PREFIX, JSON_ENDIAN_BYTE_ORDER


def send_dict_as_json_through_established_socket_connection(conn: socket.socket, data: dict) -> None:
    """
    Sends a dictionary to a socket connection in JSON format.

    Args:
        conn (socket.socket): The socket connection to send data to.
        data (dict): The dictionary to send.

    Raises:
        ValueError: If the data cannot be serialized to JSON.
        socket.error: If there's an error sending data through the socket.
    """
    try:
        # Serialize the dictionary to a JSON string
        json_data = json.dumps(data)

        # Encode the JSON string into bytes
        encoded_data = json_data.encode('utf-8')

        # Send the length of the data first (fixed 4 bytes, big-endian)
        conn.sendall(len(encoded_data).to_bytes(JSON_LENGTH_PREFIX, JSON_ENDIAN_BYTE_ORDER))

        # Send the actual JSON data
        conn.sendall(encoded_data)
    except (json.JSONDecodeError, ValueError) as e:
        raise ValueError(f"Failed to serialize dictionary to JSON: {e}")
    except socket.error as e:
        raise socket.error(f"Socket error occurred: {e}")


def receive_json_as_dict_through_established_connection(conn: socket.socket) -> dict:
    """
    Receives JSON data from a socket connection and converts it into a dictionary.

    Args:
        conn (socket.socket): The socket connection to receive data from.

    Returns:
        dict: The received JSON data as a dictionary.

    Raises:
        ValueError: If the received data is not valid JSON.
        socket.error: If there's an error receiving data through the socket.
    """
    try:
        # First, read the 4-byte length prefix
        length_prefix = conn.recv(JSON_LENGTH_PREFIX)
        if len(length_prefix) < JSON_LENGTH_PREFIX:
            raise socket.error("Incomplete length prefix received")

        # Convert the length prefix from bytes to an integer
        data_length = int.from_bytes(length_prefix, JSON_ENDIAN_BYTE_ORDER)

        # Read the actual data in chunks until the specified length is received
        received_data = b""
        while len(received_data) < data_length:
            chunk = conn.recv(data_length - len(received_data))
            if not chunk:
                raise socket.error("Connection closed before receiving all data")
            received_data += chunk

        # Decode the received bytes into a JSON string and parse it into a dictionary
        json_data = received_data.decode('utf-8')
        return json.loads(json_data)
    except (json.JSONDecodeError, ValueError) as e:
        raise ValueError(f"Failed to deserialize received data into JSON: {e}")
    except socket.error as e:
        raise socket.error(f"Socket error occurred: {e}")