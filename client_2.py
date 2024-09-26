import socket

def send_command(command):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('192.168.1.123', 9000))  # Sunucunun IP adresi ve portu

    print(f"Gönderilen komut: {command}")
    client.send(command.encode())

    if command.lower() in ['exit', 'quit']:
        return

    response = client.recv(4096)
    print(response.decode())

    client.close()

while True:
    command = input("Komut girin: ")
    send_command(command)

    if command.lower() in ['exit', 'quit']:
        break
