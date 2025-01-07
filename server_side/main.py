from server_side.Server import Server

if __name__ == "__main__":
    server_ip = "127.0.0.1"  # Bind to localhost
    server_port = 5000       # Server port
    server = Server(host_ip = server_ip, port=server_port)
    server.run()