import os, ctypes

libsnark_path = '/home/collin/Desktop/Projects/zk-dns-filter/CodeSnippets/prover/jsnark/libsnark'
arith_path = '/home/collin/Desktop/Projects/zk-dns-filter/CodeSnippets/prover/data/dot.arith'
in_path = '/home/collin/Desktop/Projects/zk-dns-filter/CodeSnippets/prover/data/dot.in'
public_in_path = '/home/collin/Desktop/Projects/zk-dns-filter/CodeSnippets/prover/data/dot_public.in'
pk_path = '/home/collin/Desktop/Projects/zk-dns-filter/CodeSnippets/prover/data/dot_pk'
pvk_path = '/home/collin/Desktop/Projects/zk-dns-filter/CodeSnippets/prover/data/dot_pvk'
proof_path = '/home/collin/Desktop/Projects/zk-dns-filter/CodeSnippets/prover/data/tmp_dot_proof'
lib = ctypes.CDLL('/home/collin/Desktop/Projects/zk-dns-filter/CodeSnippets/prover/jsnark/libsnark/build/libsnark/jsnark_interface/libpython_prove_r1cs_gg_ppzksnarkd.so')

def run_lib():
    pk = lib.read_pk(ctypes.c_char_p(pk_path.encode()))
    pvk = lib.read_pvk(ctypes.c_char_p(pvk_path.encode())) 
    proof = lib.generate_proof(ctypes.c_char_p(arith_path.encode()), ctypes.c_char_p(in_path.encode()), pk)
    r1cs_proof = ctypes.c_char_p(proof).value
    print(r1cs_proof)
    with open(public_in_path, 'r') as f:
        public_inputs = f.read()
    ans = lib.verify_proof(ctypes.c_char_p(public_inputs.encode()), ctypes.c_char_p(r1cs_proof), len(r1cs_proof), pvk)
    print(ans)

def run_lib_prove():
    pk_path = "/home/collin/Desktop/Projects/zk-dns-filter/CodeSnippets/prover/data/co_pk"
    arith_path = "/home/collin/Desktop/Projects/zk-dns-filter/CodeSnippets/prover/data/co.arith"
    in_path = "/home/collin/Desktop/Projects/zk-dns-filter/CodeSnippets/prover/data/co.in"
    pk = lib.read_pk(ctypes.c_char_p(pk_path.encode()))
    proof = lib.generate_proof(ctypes.c_char_p(arith_path.encode()), ctypes.c_char_p(in_path.encode()), pk)
    r1cs_proof = ctypes.c_char_p(proof).value
    print(r1cs_proof)

def run_lib_verify():
    pvk = lib.read_pvk(ctypes.c_char_p(pvk_path.encode()))
    with open(public_in_path, 'r') as f:
        public_inputs = f.read()
    with open('/home/collin/Desktop/Projects/zk-dns-filter/CodeSnippets/prover/data/tmp_co_proof', 'rb') as f:
        r1cs_proof = f.read()
        print(r1cs_proof)
    ans = lib.verify_proof(ctypes.c_char_p(public_inputs.encode()), ctypes.c_char_p(r1cs_proof), len(r1cs_proof), pvk)

def run_test():
    arith_path = '/home/collin/Desktop/Projects/zk-dns-filter/CodeSnippets/gen/circuits/Sudoku9x9.arith'
    in_path = '/home/collin/Desktop/Projects/zk-dns-filter/CodeSnippets/gen/circuits/Sudoku9x9_Sample_Run1.in'
    # arith_path = '/home/collin/Desktop/Projects/zk-dns-filter/CodeSnippets/prover/data/doh.arith'
    # in_path    = '/home/collin/Desktop/Projects/zk-dns-filter/CodeSnippets/prover/data/doh.in'
    command = f'{libsnark_path}/build/libsnark/jsnark_interface/run_ppzksnark gg {arith_path} {in_path}'
    os.system(command)

def run_generator():
    command = f'{libsnark_path}/build/libsnark/jsnark_interface/generate_r1cs_gg_ppzksnark {arith_path} {in_path} {pvk_path} {pk_path}'
    os.system(command)

def run_prover():
    command = f'{libsnark_path}/build/libsnark/jsnark_interface/prove_r1cs_gg_ppzksnark {arith_path} {in_path} {pk_path} tmp_proof'
    os.system(command)
    # print(command.split(' '))

def run_verifier():
    command = f'{libsnark_path}/build/libsnark/jsnark_interface/verify_r1cs_gg_ppzksnark {in_path} {pvk_path} {proof_path} 165 ans'
    os.system(command)

if __name__ == '__main__':
    # run_generator()
    # run_prover()
    run_test()
    # run_lib_prove()
