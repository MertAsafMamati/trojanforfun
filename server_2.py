import socket

def start_server(host, port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(1)
    print(f"[*] Listening on {host}:{port}")

    while True:
        client_socket, addr = server.accept()
        print(f"[*] Received IP address from {addr}")
        ip_address = client_socket.recv(1024).decode()
        print(f"Received IP address: {ip_address}")
        client_socket.close()

if __name__ == "__main__":
    host = "0.0.0.0"  # Sunucunun IP adresi (0.0.0.0 tüm IP adreslerinden gelen bağlantıları kabul eder)
    port = 9000       # Sunucunun port numarası
    start_server(host, port)
