import asyncio, os, traceback, base64, requests, ctypes, uuid, logging, time, sys, random, subprocess
import datetime
import signal
from multiprocessing import Process, Value
from typing import Any, Dict, List
from dnslib import DNSRecord
from tlslite.api import TLSConnection
from tlslite import TLSConnection, HandshakeSettings
from socket import socket, AF_INET, SOCK_STREAM, IPPROTO_TCP, TCP_NODELAY
from tools.dropbox_downloader import get_dropbox_file
from proxy.merkle.poseidon_hash import PoseidonHashGenerator
from proxy.merkle.non_membership_proof_clean import MerkelWitnessGenerator
from proxy.witness.handshake_info import HandshakeInfoGenerator
from tools.libcirc import CircuitProver, zkmb_prove, zkmb_get_prover
import numpy as np
import json, threading
from chacha20poly1305 import ChaCha20Poly1305
from queue import Queue
import psutil
import re
from proxy.regex_prover import RegexAsyncProver

HOST, PORT = "192.168.0.1", 8080
dot_proof_api = f"http://{HOST}:{PORT}/amortized_proof"
co_dot_proof_api = f"http://{HOST}:{PORT}/channel_open_proof"
precomp_proof_api = f"http://{HOST}:{PORT}/precompute_proof"
logging.basicConfig(stream=sys.stdout, level=logging.INFO)

hex_to_u8_arr = lambda arr : [int(arr[i:i+2], 16) for i in range(0, len(arr), 2)]
batch_size = 16

def base64_encode(string):
    """
    Removes any `=` used as padding from the encoded string.
    """
    encoded = base64.urlsafe_b64encode(string).decode('utf-8')
    return encoded.rstrip("=")

def chacha_seal(key: str, iv: str, seq_num: int, message) -> bytes:
    message = message + b'\x17'
    key = bytes.fromhex(key)
    iv = bytes.fromhex(iv)
    cip = ChaCha20Poly1305(key)
    iv = (int(bytes(iv).hex(), 16) ^ seq_num).to_bytes(12, byteorder='big')
    out_len = len(message) + 16
    # this is just recreated Record Layer header
    authData = bytearray([23, 3, 3, out_len // 256, out_len % 256])
    pad = cip.seal(iv, message, authData)
    result = [int(b) for b in pad]
    logging.info(f"ChaCha before encrypted is {message}")
    print(pad.hex())
    return result

def test():
    server_socket = socket(AF_INET, SOCK_STREAM)
    server_socket.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
    server_socket.connect(('8.8.8.8', 853))
    server_connection = TLSConnection(server_socket)
    settings = HandshakeSettings()
    settings.versions = [(3, 4)]
    settings.cipherNames = ["chacha20-poly1305"]
    settings.eccCurves = ["secp256r1"]
    settings.keyShares = ["secp256r1"]
    server_connection.handshakeClientCert(settings=settings, print_handshake=False)
    record = DNSRecord.question('amazon.com', "A")
    id = record.header.id
    data = record.pack()
    data_len_hex = hex(len(data))[2:]
    prefix_hex = '0' * (4 - len(data_len_hex)) + data_len_hex
    message_hex = prefix_hex + data.hex()
    message = bytearray.fromhex(message_hex)
    c_ap_key = server_connection._recordLayer._writeState.encContext.key.hex()
    c_ap_iv = server_connection._recordLayer._writeState.fixedNonce.hex()
    # chacha_seal(c_ap_key, c_ap_iv, 0, message)
    for idx in range(2000):
        print(idx)
        server_connection.write(message)
        response = server_connection.read()
    print("response", response)
    # ciphertexts = server_connection._recordLayer.ciphertextMessage
    # ciphertext = ciphertexts[-1].write().hex()
    # print("ciphertext", ciphertext)