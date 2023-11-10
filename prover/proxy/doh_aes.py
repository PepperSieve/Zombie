import asyncio, os, traceback, base64, requests, ctypes, uuid, logging
from dnslib import DNSRecord
from tlslite.api import TLSConnection
from tlslite import TLSConnection, HandshakeSettings
from socket import socket, AF_INET, SOCK_STREAM
from non_membership_testing.poseidon_hash import PoseidonHashGenerator
from zkbackend import CircuitProver, Groth16Prover, SpartanProver
from non_membership_testing.non_membership_proof_clean import MerkelWitnessGenerator
from handshake_info import HandshakeInfoGenerator

HOST, PORT = "10.0.0.1", 8080
doh_proof_api = f"http://{HOST}:{PORT}/doh_proof"
co_doh_proof_api = f"http://{HOST}:{PORT}/co_proof" 
logging.basicConfig(level=logging.INFO)

def base64_encode(string):
    """
    Removes any `=` used as padding from the encoded string.
    """
    encoded = base64.urlsafe_b64encode(string).decode('utf-8')
    return encoded.rstrip("=")


class DohAESProxy:
    def __init__(self, backend, NEED_PROOF):
        if NEED_PROOF:
            try:
                requests.post(doh_proof_api + '/test', json={'test': 'test'})
            except:
                raise NotImplementedError
            co_prover = DohChannelOpenProver(backend)
            self.dns_prover = DohAESProver(backend)
        server_socket = socket(AF_INET, SOCK_STREAM)
        server_socket.connect(('1.1.1.1', 443))
        self.server_connection = TLSConnection(server_socket)
        settings = HandshakeSettings()
        settings.versions = [(3, 4)]
        settings.cipherNames = ["aes128gcm"]
        settings.eccCurves = ["secp256r1"]
        settings.keyShares = ["secp256r1"]
        self.SN = 0
        self.NEED_PROOF = NEED_PROOF
        self.server_connection.handshakeClientCert(settings=settings, print_handshake=True)
        self.send_sample_request(False)
        if NEED_PROOF:
            self.c_ap_key = self.server_connection._recordLayer._writeState.encContext.key.hex()
            self.c_ap_iv = self.server_connection._recordLayer._writeState.fixedNonce.hex()
            proof = co_prover.generate_proof({'conn': self.server_connection})
            json_proof = {
                'comm': self.dns_prover.get_comm(self.c_ap_key, self.c_ap_iv),
                'r1cs_proof': proof.hex()
            }
            requests.post(co_doh_proof_api, json=json_proof)
        self.send_sample_request(NEED_PROOF)

    def send_sample_request(self, TEST_PROVE):
        sample_doh_request = "GET /dns-query?dns=4YABAAABAAAAAAAABmFtYXpvbgNjb20AAAEAAQ HTTP/1.1\r\nHost: 1.1.1.1\r\nAccept-Encoding: identity\r\nAccept: application/dns-message\r\n\r\n"
        self.server_connection.write(sample_doh_request.encode('utf-8'))
        if TEST_PROVE:
            self.prove_dns("amazon.com")
        self.SN += 1
        first_response = self.server_connection.read()
        logging.info(first_response)
    
    def prove_dns(self, domain):
        ciphertexts = self.server_connection._recordLayer.ciphertextMessage
        dns_ct = ciphertexts[-1].write().hex()
        dns_ciphertext = dns_ct[0:-17]
        packet_id = dns_ciphertext[:10]
        proof = self.dns_prover.generate_proof({'key': self.c_ap_key, 'iv': self.c_ap_iv, 'dns_ciphertext': dns_ciphertext, 'SN': self.SN, 'domain': domain})
        print("generate proof finish")
        try:
            json_proof = {
                'packet_id': packet_id,
                'SN': self.SN,
                'r1cs_proof': proof.hex()
            }
            logging.info("will send proof")
            requests.post(doh_proof_api, json=json_proof)
            logging.info("send proof finish")
        except Exception as e:
            logging.debug(e)

    def forward_data(self, data):
        b64_dnsq = base64_encode(data)
        doh_request = f"GET /dns-query?dns={b64_dnsq} HTTP/1.1\r\nHost: 1.1.1.1\r\nAccept-Encoding: identity\r\nAccept: application/dns-message\r\n\r\n"
        self.server_connection.write(doh_request.encode('utf-8'))
        request = DNSRecord.parse(data)
        domain = '.'.join(
            list(map(lambda x: x.decode('utf-8'), request.questions[0].qname.label)))
        if self.NEED_PROOF:
            self.prove_dns(domain)
        self.SN += 1
        logging.info("will read")
        # if this block, the whole program will block and no packet will be processed
        # set a timeout for this
        server_response = self.server_connection.read().split(b'\r\n')
        logging.info("read finish")
        if len(server_response) <= 2 or server_response[-2] != b'':
            return None
        else:
            body = server_response[-1]
            reply = DNSRecord.parse(body)
            return reply 


class DohAESProver(CircuitProver):
    def __init__(self, backend):
        super().__init__('DohAES', 'http://localhost:8000', backend)
        if backend == "Groth16":
            self.proof_generator = Groth16Prover('./data/Groth16_doh.arith', "doh", True)
            self.merkel_generator = MerkelWitnessGenerator("/mydata/blocklist.txt", "/mydata/bn128_pre.txt")
            self.hash_generator = PoseidonHashGenerator('bn128')
        elif backend == "Spartan":
            self.proof_generator = SpartanProver("./data/Spartan_doh.arith", "doh", True)
            self.merkel_generator = MerkelWitnessGenerator("/mydata/blocklist.txt", "/mydata/dalek_pre.txt")
            self.hash_generator = PoseidonHashGenerator('dalek')
        else:
            raise NotImplementedError
        print("root", self.merkel_generator.root)

    def get_comm(self, key, iv):
        comm = hex(self.hash_generator.poseidon_hash([0, int(key + iv, 16)]))[2:] 
        return comm
    
    def generate_transcript(self, value_dict):
        key = value_dict['key']
        iv = value_dict['iv']
        dns_ciphertext = value_dict['dns_ciphertext']
        domain = value_dict['domain']
        SN = value_dict['SN']
        comm = hex(self.hash_generator.poseidon_hash([0, int(key + iv, 16)]))[2:]
        amortized_doh_inputs = '\n'.join([comm, dns_ciphertext, key, iv, str(SN)]) + '\n'
        test_wildcard = self.merkel_generator.generate(domain)
        transcript = {
            "amortized_doh_inputs": amortized_doh_inputs,
            "membership_test": test_wildcard
        }
        return transcript
        


class DohChannelOpenProver(CircuitProver):
    def __init__(self, backend):
        super().__init__('DohAESCO', 'http://localhost:8001', backend)
        if backend == "Groth16":
            self.proof_generator = Groth16Prover("./data/Groth16_co_doh.arith", "co_doh", True)
            self.hs_generator = HandshakeInfoGenerator('bn128', 'aes128gcm')
        elif backend == "Spartan":
            self.proof_generator = SpartanProver("./data/Spartan_co_doh.arith", "co_doh", True)
            self.hs_generator = HandshakeInfoGenerator('dalek', 'aes128gcm')
        else:
            raise NotImplementedError
    
    def generate_transcript(self, value_dict):
        conn = value_dict['conn']
        handshake_info = self.hs_generator.get_handshake_info(conn)
        transcript = {
            "handshake_info": handshake_info
        }
        return transcript


if __name__ == '__main__':
    DohAESProxy("Spartan", True)
    # DohAESProxy("Groth16", True)