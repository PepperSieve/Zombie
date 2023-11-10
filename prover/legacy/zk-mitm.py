# Author: Collin Zhang

from socket import *
from tlslite.api import TLSConnection
from tlslite import *
from generate_test import get_test_values, print_test, get_doh_test
from non_membership_testing.non_membership_proof_clean import wildcard_non_membership_witness
import base64
from dnslib import DNSRecord
import os


def base64_decode(string):
    """
    Adds back in the required padding before decoding.
    """
    padding = 4 - (len(string) % 4)
    string = string + ("=" * padding)
    return base64.urlsafe_b64decode(string)


if __name__ == '__main__':
    HOST = "127.0.0.1"  # Standard loopback interface address (localhost)
    PORT = 65432  # Port to listen on (non-privileged ports are > 1023)
    s = open("./mitm.crt").read()
    x509 = X509()
    x509.parse(s)
    cert_chain = X509CertChain([x509])
    s = open("./mitm.key").read()
    privateKey = parsePEMKey(s, private=True)

    mitm_socket = socket.socket(AF_INET, SOCK_STREAM)
    mitm_socket.bind((HOST, PORT))
    mitm_socket.listen()
    conn, addr = mitm_socket.accept()
    client_connection = TLSConnection(conn)
    with conn:
        print(f"Connected by {addr}")
        while True:
            # handle HTTP CONNECT request as proxy
            data = conn.recv(1024)
            data = data.decode('utf-8')
            splitted_data = data.split(' ')
            if splitted_data[0] == 'CONNECT':
                host, port = splitted_data[1].split(':')
                conn.send(b"HTTP/1.1 200 OK\r\n\r\n")
                break
        client_connection.handshakeServer(certChain=cert_chain, privateKey=privateKey, alpn=['HTTP/1.1'])
        client_request = client_connection.read()
        print("client request", client_request)

        # check for dns request
        if host == '1.1.1.1':
            try:
                request = client_request.decode('utf-8')
                print(request)
                data = request.split(' ')[1].split('=')[1]
                data = base64_decode(data)
                record = DNSRecord.parse(data)
                domain = '.'.join(list(map(lambda x : x.decode('utf-8'), record.questions[0].qname.label)))
                print("domain is", domain)
            except:
                pass
        
        # connection with remote server
        server_socket = socket.socket(AF_INET, SOCK_STREAM)
        server_socket.connect((host, int(port)))
        server_connection = TLSConnection(server_socket)
        settings = HandshakeSettings()
        settings.versions = [(3, 4)]
        settings.cipherNames = ["aes128gcm"]
        settings.eccCurves = ["secp256r1"]
        settings.keyShares = ["secp256r1"]
        server_connection.handshakeClientCert(settings=settings, print_handshake=True)

        # send request and forward it back
        server_connection.write(client_request)
        server_response = server_connection.read()
        print("server response", server_response)
        client_connection.write(server_response)
        client_connection.close()

        # prove
        if domain:
            test_dict = get_test_values(server_connection)
            test_doh = get_doh_test(test_dict)
            test_wildcard = wildcard_non_membership_witness(domain, './non_membership_testing/pi_blocklist_all.list.txt', './non_membership_testing/wildcard_new_pre.txt')
            # change to your zkmbs folder with updated jsnark installed
            os.chdir('/home/collin/Desktop/Projects/zkmb-client/zkmbs')
            with open("./gen/test_doh.txt", "w") as f:
                f.write(test_doh)
            with open("./gen/test_wildcard.txt", "w") as f:
                f.write(test_wildcard)
            # TODO: check if the code is really using the input file
            os.system("java -Xmx10g -cp gen/bin:gen/xjsnark_backend.jar xjsnark.e2eDNS.DNS_Shortcut_doh_get")
            os.system("./jsnark/libsnark/build/libsnark/jsnark_interface/prove_r1cs_gg_ppzksnark \
                ./gen/circuits/DNS_Shortcut_doh_get_optimized.arith \
                ./gen/circuits/DNS_Shortcut_doh_get_Sample_Run1_optimized.in \
                test_proof_1")