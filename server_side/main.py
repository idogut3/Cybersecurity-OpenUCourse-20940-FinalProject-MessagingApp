from GlobalConstants import SERVER_IP, SERVER_PORT
from server_side.Server import Server

if __name__ == "__main__":
    # server_ip = "127.0.0.1"
    # server_port = 5000
    server_ip = SERVER_IP # Bind to localhost
    server_port = SERVER_PORT # Server port
    server = Server(host_ip = server_ip, port=server_port)
    server.run()