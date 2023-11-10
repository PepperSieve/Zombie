import asyncio
from dnslib import DNSRecord
from tlslite.api import TLSConnection
from tlslite import TLSConnection, HandshakeSettings
from socket import socket, AF_INET, SOCK_STREAM
import os
from non_membership_testing.poseidon_hash import poseidon_hash
from generate_test import get_handshake_info
import requests

HOST, PORT = "10.0.0.1", 8080

server_socket = socket(AF_INET, SOCK_STREAM)
server_socket.connect(('1.1.1.1', 443))
server_connection = TLSConnection(server_socket)
settings = HandshakeSettings()
settings.versions = [(3, 4)]
settings.cipherNames = ["aes128gcm"]
settings.eccCurves = ["secp256r1"]
settings.keyShares = ["secp256r1"]
server_connection.handshakeClientCert(settings=settings, print_handshake=False)
handshake_info = get_handshake_info(server_connection)

json_inputs = {
    "handshake_info": handshake_info
}
response = requests.post("http://localhost:8001/generate_assignment", json=json_inputs)
print(response.text)