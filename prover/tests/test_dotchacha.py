from socket import socket, AF_INET, SOCK_STREAM
from tlslite import TLSConnection, HandshakeSettings
import requests, base64, os
from generate_test import get_handshake_info
from dnslib import DNSRecord
from non_membership_testing.poseidon_hash import PoseidonHashGenerator
from non_membership_testing.non_membership_proof_clean import MerkelWitnessGenerator
import ctypes, uuid, time
from zkbackend import SpartanProver

def get_cstr(str):
    return ctypes.c_char_p(str.encode())

def generate_proof(arith_path, r1cs_assignment, pk):
    uid = str(uuid.uuid4())
    in_path = os.path.join(current_path, f'data/{uid}.in')
    proof_path = os.path.join(current_path, f'data/{uid}_proof')
    with open(in_path, 'w+') as f:
        f.write(r1cs_assignment)
    lib.generate_proof(get_cstr(arith_path), get_cstr(in_path), get_cstr(proof_path), pk)
    with open(proof_path, 'rb') as f:
        proof = f.read()
        return proof

def base64_encode(string):
    """
    Removes any `=` used as padding from the encoded string.
    """
    encoded = base64.urlsafe_b64encode(string).decode('utf-8')
    return encoded.rstrip("=")

doh_api = "http://localhost:8000"
co_api  = "http://localhost:8001"
dot_api = "http://localhost:8002"

server_socket = socket(AF_INET, SOCK_STREAM)
server_socket.connect(('1.1.1.1', 853))
server_connection = TLSConnection(server_socket)
settings = HandshakeSettings()
settings.versions = [(3, 4)]
settings.cipherNames = ["chacha20-poly1305"]
settings.eccCurves = ["secp256r1"]
settings.keyShares = ["secp256r1"]
server_connection.handshakeClientCert(
    settings=settings, print_handshake=False)
c_ap_key = server_connection._recordLayer._writeState.encContext.key.hex()
c_ap_iv = server_connection._recordLayer._writeState.fixedNonce.hex()
concat = '0' * 40 + c_ap_key + c_ap_iv
comm = hex(PoseidonHashGenerator('dalek').poseidon_hash([int(concat[:64], 16), int(concat[64:], 16)]))[2:]
handshake_info = get_handshake_info(server_connection)
path_dict = {}
current_path = os.getcwd()
path_dict['blocklist_path'] = os.path.join(current_path, 'data/dalek_blocklist.txt')
path_dict['pre_path'] = os.path.join(current_path, 'data/dalek_pre.txt')
path_dict['dot_arith_path'] = os.path.join(current_path, 'data/dot.arith')
path_dict['dot_pk_path'] = os.path.join(current_path, 'data/dot_pk')
path_dict['lib_so_path'] = os.path.join(current_path, 'jsnark/libsnark/build/libsnark/jsnark_interface/libpython_prove_r1cs_gg_ppzksnark.so')
# lib = ctypes.CDLL(path_dict['lib_so_path'])

domain = 'amazon.com'
data = DNSRecord.question(domain,"A").pack()
data_len_hex = hex(len(data))[2:]
prefix_hex = '0' * (4 - len(data_len_hex)) + data_len_hex
message_hex = prefix_hex + data.hex()
message = bytearray.fromhex(message_hex)
print("write")
start = time.time()
server_connection.write(message)
end = time.time()
print("write finish", end - start)
witness_generator = MerkelWitnessGenerator(path_dict['blocklist_path'], path_dict['pre_path'])

start = time.time()
ciphertexts = server_connection._recordLayer.ciphertextMessage
dot_ct = ciphertexts[-1].write().hex()
end = time.time() 
print("before wildcard", end - start)
membership_test = witness_generator.generate(domain)
end = time.time() 
print("after wildcard", end - start)
json_inputs = {
    "comm_str": comm,
    "key_str": c_ap_key,
    "nonce_str": c_ap_iv, 
    "dns_ct_str": dot_ct,
    "membership_test": membership_test
}
end = time.time()
print("generate textual inputs", end - start)
print("send request")
start = time.time()
response = requests.post(f"{dot_api}/generate_assignment", json=json_inputs)
end = time.time()
print("read response, time", end - start)
with open(os.path.join(current_path, 'data/dot.in'), 'w') as f:
    f.write(response.text)

# prover = SpartanProver('placeholder')
# prover.prove('/home/ubuntu/collin/libsnark/dot.arith', os.path.join(current_path, 'data/dot.in'))
# start = time.time()
# os.system("./jsnark/libsnark/build/libsnark/jsnark_interface/print_r1cs gg ./data/dot.arith ./data/dot.in >> ../../../Spartan/custom_r1cs_input.txt")
# end = time.time()
# print("generate input", end - start)
# os.chdir("../../../Spartan")
# os.system("/home/collin/.cargo/bin/cargo bench")
# print("read pk")
# start = time.time()
# dot_pk = lib.read_pk(ctypes.c_char_p(path_dict['dot_pk_path'].encode()))
# end = time.time()
# print("read pk finish", end - start)
# generate_proof(path_dict['dot_arith_path'], response.text, dot_pk)
