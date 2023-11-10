import ctypes
import os
import shutil

libcirc_dict = {}

def get_cstr(s):
    return ctypes.c_char_p(s.encode())

# this is a hack
# python doesn't allow multiple process to use the same shared library
# as a result, we make a copy of the shared library
def get_libcirc():
    pid = os.getpid()
    if pid not in libcirc_dict:
        so_path = '../circ/target/release/libcirc_zkmb.so'
        new_path = f"../circ/target/release/libcirc_zkmb_{pid}.so"
        if os.path.exists(so_path):
            shutil.copy(so_path, new_path)
            print("File might be copied successfully")
        else:
            print("File not found.")
        libcirc = ctypes.CDLL(new_path)
        # try:
        #     libcirc = ctypes.CDLL('../circ/target/release/libcirc_zkmb.so')
        # except:
        #     libcirc = ctypes.CDLL('../circ/target/release/libcirc_zkmb.dylib')
        libcirc.zkmb_get_prover.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
        libcirc.zkmb_get_prover.restype = ctypes.c_void_p
        libcirc.zkmb_prove.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
        libcirc.zkmb_prove.restype = None
        libcirc_dict[pid] = libcirc
    return libcirc_dict[pid]

def get_dot_chacha_verifier(inst_path: str, gens_path: str, input_names_path: str):
    libcirc = get_libcirc()
    return libcirc.get_dot_chacha_verifier(get_cstr(inst_path), get_cstr(gens_path), get_cstr(input_names_path))

def verify_dot_chacha_proof(verifier, witness: str, proof: str) -> bool:
    libcirc = get_libcirc()
    return libcirc.verify_dot_chacha_proof(verifier, get_cstr(witness), get_cstr(proof))

def zkmb_get_prover(circuit):
    import os
    print(os.getcwd())
    inst_path = get_cstr('/mydata/' + circuit + '_inst')
    gens_path = get_cstr('/mydata/' + circuit + '_gens')
    term_arr_path = get_cstr('/mydata/' + circuit + '_term_arr')
    input_idxes_path = get_cstr('/mydata/' + circuit + '_input_idxes')
    var_idxes_path = get_cstr('/mydata/' + circuit + '_var_idxes')
    libcirc = get_libcirc()
    return libcirc.zkmb_get_prover(inst_path, gens_path, term_arr_path, input_idxes_path, var_idxes_path)

def zkmb_prove(circuit, prover, witness_list: str):
    libcirc = get_libcirc()
    libcirc.zkmb_prove(get_cstr(circuit), prover, get_cstr(witness_list), get_cstr(f'{circuit}_proof'))
    with open(f'{circuit}_proof', 'rb') as f:
        return f.read()

class CircuitProver:
    def generate_proof(self, value_dict):
        witness = self.generate_witness(value_dict)
        return self.lib_prove(witness)

# if __name__ == '__main__':
#     import os
#     os.chdir('./circ')
#     libcirc = get_libcirc()
#     generate_dot_co_keys("co_inst", "co_gens")
#     # generate_dot_chacha_keys('amortized_inst', 'amortized_gens')
