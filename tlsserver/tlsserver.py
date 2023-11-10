import socket
import ssl
import threading

HOST = '0.0.0.0'
PORT = 853
CERT_FILE = 'cert.pem'
KEY_FILE = 'key.pem'

def handle_client(conn, client_address):
    print(f"Connection from {client_address}")

    # Receive data and send it back
    try:
        while True:
            data = conn.recv(1024)
            if not data:
                continue
            conn.send(data)
            # print(f"Received data from {client_address}: {data}")
    except Exception as e:
        print(f"Error handling client {client_address}: {e}")

    # Close the connection
    conn.shutdown(socket.SHUT_RDWR)
    conn.close()
    print(f"Connection closed for {client_address}")

# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind((HOST, PORT))
sock.listen(50)

# Wrap the socket with SSL/TLS
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
# context.set_ciphers("TLS_CHACHA20_POLY1305_SHA256")
context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)

print(f"TLS server started on {HOST}:{PORT}")

while True:
    # Accept connections
    client_socket, client_address = sock.accept()

    # Wrap the client socket with SSL/TLS
    conn = context.wrap_socket(client_socket, server_side=True)

    # Create a new thread to handle the client connection
    client_thread = threading.Thread(target=handle_client, args=(conn, client_address))
    client_thread.daemon = True  # Allows the main thread to exit even if client threads are still running
    client_thread.start()