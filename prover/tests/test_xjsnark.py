import requests
import os

os.chdir('/home/collin/Desktop/Projects/zk-dns-filter/CodeSnippets/gen')

libsnark_path = '/home/collin/Desktop/Projects/zk-dns-filter/CodeSnippets/prover/jsnark/libsnark'
doh_arith_path = '/home/collin/Desktop/Projects/zk-dns-filter/CodeSnippets/gen/circuits/DNS_Amortized_doh_get.arith'
doh_in_path = '/home/collin/Desktop/Projects/zk-dns-filter/CodeSnippets/test_keys/DNS_Amortized_doh_get_Sample_Run1.in'
CO_arith_path = '/home/collin/Desktop/Projects/zk-dns-filter/CodeSnippets/test_keys/CO.arith'
CO_in_path = '/home/collin/Desktop/Projects/zk-dns-filter/CodeSnippets/test_keys/CO.in'
test_keys_path = '/home/collin/Desktop/Projects/zk-dns-filter/CodeSnippets/test_keys'

def run_prover(arith_path, in_path, pk_path):
    command = f'{libsnark_path}/build/libsnark/jsnark_interface/prove_r1cs_gg_ppzksnark {arith_path} {in_path} {pk_path} {test_keys_path}/tmp_proof'
    os.system(command)
    # print(command.split(' '))

def run_verifier(in_path, num, pvk_path):
    command = f'{libsnark_path}/build/libsnark/jsnark_interface/verify_r1cs_gg_ppzksnark {in_path} {pvk_path} {test_keys_path}/tmp_proof {num}'
    os.system(command)

with open('handshake_info', 'r') as f:
    handshake_info = f.read() 

with open('amortized_doh_inputs.txt', 'r') as f:
    amortized_doh_inputs = f.read()

with open('test_wildcard.txt', 'r') as f:
    test_wildcard = f.read()

json_inputs = {
    "handshake_info": handshake_info
}
response = requests.post("http://localhost:8001/generate_channel", json=json_inputs)
print("get response")
with open(CO_in_path, 'w') as f:
    f.write(response.text)
run_prover(CO_arith_path, CO_in_path,
'/home/collin/Desktop/Projects/zk-dns-filter/CodeSnippets/test_keys/CO_pk')
run_verifier(CO_in_path, 165,
'/home/collin/Desktop/Projects/zk-dns-filter/CodeSnippets/test_keys/CO_pvk')


json_inputs = {
    "amortized_doh_inputs": amortized_doh_inputs,
    "membership_test": test_wildcard
}
response = requests.post("http://localhost:8000/generate_assignment", json=json_inputs)
print("get response")
with open(doh_in_path, 'w') as f:
    f.write(response.text)
run_prover(doh_arith_path, doh_in_path,
'/home/collin/Desktop/Projects/zk-dns-filter/CodeSnippets/test_keys/doh_pk')
run_verifier(doh_in_path, 504,
'/home/collin/Desktop/Projects/zk-dns-filter/CodeSnippets/test_keys/doh_pvk')

json_inputs = {
    "amortized_doh_inputs": amortized_doh_inputs,
    "membership_test": test_wildcard
}
response = requests.post("http://localhost:8000/generate_assignment", json=json_inputs)
print("get response")
with open(doh_in_path, 'w') as f:
    f.write(response.text)
run_prover(doh_arith_path, doh_in_path,
'/home/collin/Desktop/Projects/zk-dns-filter/CodeSnippets/test_keys/doh_pk')
run_verifier(doh_in_path, 504,
'/home/collin/Desktop/Projects/zk-dns-filter/CodeSnippets/test_keys/doh_pvk')
print("all finished")