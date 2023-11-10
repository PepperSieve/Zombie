import requests, logging, time, threading, json
from tools.libcirc import zkmb_prove, zkmb_get_prover
from typing import Any, Dict, List
from proxy.merkle.poseidon_hash import PoseidonHashGenerator
from multiprocessing import Process, Value
from chacha20poly1305 import ChaCha20Poly1305
import psutil

HOST, PORT = "192.168.0.1", 8080
dot_proof_api = f"http://{HOST}:{PORT}/amortized_proof"
hex_to_u8_arr = lambda arr : [int(arr[i:i+2], 16) for i in range(0, len(arr), 2)]
HOST, PORT = "192.168.0.1", 8080
precomp_proof_api = f"http://{HOST}:{PORT}/precompute_proof"
SEND_REAL_PROOF = True

batch_size = 16

def get_pad_comm(pad: bytes, hash_generator):
    pad += b'\x00' * (9 * 31 - 255)
    pad_comm = 0
    for idx in range(9):
        pad_comm = hash_generator.poseidon_hash([pad_comm, int(pad[idx * 31: idx * 31 + 31].hex(), 16)])
    return str(pad_comm)

def get_pad(key: str, iv: str, seq_num: int) -> bytes:
    key = bytes.fromhex(key)
    iv = bytes.fromhex(iv)
    cip = ChaCha20Poly1305(key)
    iv = (int(bytes(iv).hex(), 16) ^ seq_num).to_bytes(12, byteorder='big')
    pad = cip.encrypt(iv, b'\x00' * 255)[:255]
    return pad

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

class RegexProver:
    def __init__(self, MIDDLEBOX_ACTIVE, should_precompute, key, nonce):
        self.MIDDLEBOX_ACTIVE = MIDDLEBOX_ACTIVE
        self.enable_precomp = should_precompute
        if should_precompute:
            self.prover = zkmb_get_prover('RegexChaChaAmortizedUnpack')
        else:
            self.prover = zkmb_get_prover('RegexChaChaAmortized')
        self.hash_generator = PoseidonHashGenerator('dalek')
        if should_precompute:
            # start background thread to precompute
            comm = hex(self.hash_generator.poseidon_hash([int(key, 16), int(nonce, 16)]))[2:]
            comm = str(int(comm, 16))
            self.pad_seq_num = Value('i', 0)
            self.traffic_seq_num = Value('i', 0)
            p = Process(target=self.precompute_pads, args=(key, nonce, comm, self.pad_seq_num, self.traffic_seq_num))
            p.start()
            self.precomp_pid = p.pid

    def precompute_pads(self, key, nonce, comm, pad_seq_num, traffic_seq_num):
        circuit = 'PrecompDotChaCha'
        prover = zkmb_get_prover(circuit)
        pad_seq_num.value = 0
        logging.info("enter precompute pads")
        while True:
            while pad_seq_num.value - traffic_seq_num.value > 64:
                time.sleep(0.1)
            prover_witnesses = []
            comm_list = []
            pad_comm_list = []
            seq_num_list = []
            for idx in range(batch_size):
                prover_witnesses.append({'comm': comm, 'SN': pad_seq_num.value + idx, 'key': hex_to_u8_arr(key), 'nonce': hex_to_u8_arr(nonce)})
                pad_comm = get_pad_comm(get_pad(key, nonce, pad_seq_num.value + idx), self.hash_generator)
                comm_list.append(comm)
                pad_comm_list.append(pad_comm)
                seq_num_list.append(pad_seq_num.value + idx)
            t1 = time.time()
            proof = zkmb_prove(circuit, prover, json.dumps(prover_witnesses))
            t2 = time.time()
            logging.info(f"Precomp {len(prover_witnesses)} takes {t2 - t1:.03f}")
            # calculate pad_comm
            if self.MIDDLEBOX_ACTIVE:
                json_proof = {"r1cs_proof": proof.hex(), "comm_list": comm_list, "pad_comm_list": pad_comm_list, "seq_num_list": seq_num_list}
                response = requests.post(precomp_proof_api, json=json_proof)
            logging.info(f"Precomp response")
            logging.info(f"seq num proved {pad_seq_num.value}")
            pad_seq_num.value += batch_size

    def batch_prove_amortized(self, value_dict_list: List[Dict]):
        logging.info(f"Will batch_prove_amortized")
        t1 = time.time()
        witness_list = self.generate_witness_list(value_dict_list, self.enable_precomp)
        logging.info("Got witness list")
        t2 = time.time()
        logging.info(f"Finish generating witness takes {t2 - t1}")
        if self.enable_precomp:
            max_seq_num = max([witness['SN'] for witness in value_dict_list])
            # TODO: shall we update this earlier?
            self.traffic_seq_num.value = max_seq_num
            while self.pad_seq_num.value <= max_seq_num:
                time.sleep(0.1)
            t3 = time.time()
            # set the priority of the process lower, then set it back
            p = psutil.Process(self.precomp_pid)
            # p.nice() get the current priority, now we subtract it by 1
            current_priority = p.nice()
            logging.info(f"Current priority is {current_priority}")
            p.nice(current_priority - 1)
            proof = zkmb_prove('RegexChaChaAmortizedUnpack', self.prover, witness_list)
            p.nice(current_priority)
        else:
            t3 = time.time()
            logging.info(f"proof size {30176 * len(value_dict_list)}")
            if SEND_REAL_PROOF:
                logging.info("Send real proof")
                proof = zkmb_prove('RegexChaChaAmortized', self.prover, witness_list)
            else:
                logging.info("Send fake proof")
                proof = b'0' * 30176 * len(value_dict_list)
        t4 = time.time()
        logging.info(f"Batch generating {len(value_dict_list)} proofs takes {t4 - value_dict_list[0]['start_time']:0.3f} seconds")
        if self.MIDDLEBOX_ACTIVE:
            threading.Thread(target=self.send_proof, args=(value_dict_list, proof)).start()

    def generate_single_witness(self, value_dict, enable_precomp):
        key = value_dict['key']
        iv = value_dict['iv']
        ciphertext = value_dict['ciphertext']
        SN = value_dict['SN']
        comm = hex(self.hash_generator.poseidon_hash([int(key, 16), int(iv, 16)]))[2:]
        t1 = time.time()
        t2 = time.time()
        logging.info("Before chacha encrypt message")
        witness = {
            "ciphertext": ciphertext,
            "SN": SN
        }
        logging.info(f"Predicted ciphertext for SN {SN} is {witness['ciphertext']}")
        if enable_precomp:
            pad = get_pad(key, iv, SN)
            pad_comm = get_pad_comm(pad, self.hash_generator)
            witness['pad'] = hex_to_u8_arr(pad.hex())
            witness['comm_pad'] = pad_comm
            logging.info(f"precomputed witness {witness['comm_pad']} {witness['ciphertext']}")
        else:
            witness["comm"] = str(int(comm, 16))
            witness["key"] = hex_to_u8_arr(key)
            witness["nonce"] = hex_to_u8_arr(iv)
        return witness

    def generate_witness_list(self, value_dict_list, enable_precomp) -> str:
        witness_list = []
        for value_dict in value_dict_list:
            witness_list.append(self.generate_single_witness(value_dict, enable_precomp))
        return json.dumps(witness_list)

    def send_proof(self, value_dict_list, proof):
        logging.info("Will send proof")
        t1 = time.time()
        try:
            batch_start = value_dict_list[0]['SN']
            batch_end = value_dict_list[-1]['SN']
            json_proof = {
                'is_precomputed': self.enable_precomp,
                'batch_start': value_dict_list[0]['SN'],
                'batch_end': value_dict_list[-1]['SN'],
                'r1cs_proof': proof.hex()
            }
            response = requests.post(dot_proof_api, json=json_proof)
            logging.info(f"Send proof of batch size {batch_end - batch_start + 1}")
            logging.info(f"response is {response}")
        except Exception as e:
            logging.info(e)
        t2 = time.time()


class RegexAsyncProver:
    class ProverThread(threading.Thread):
        def __init__(self, cv: threading.Condition, proof_queue: List, prover: RegexProver, should_batch: bool, batch_wait_time: float):
            self.cv = cv
            self.proof_queue = proof_queue
            self.prover = prover
            self.should_batch = should_batch
            self.batch_wait_time = batch_wait_time
            super().__init__()

        def run(self):
            logging.info("start running")
            if self.should_batch:
                while True:
                    value_dict_list = []
                    with self.cv:
                        batch_size = len(self.proof_queue)
                        # test ddos prevention
                        # batch_size = min(batch_size, 8)
                        if batch_size > 0:
                            logging.info(f"batch size is {batch_size}")
                            for _ in range(batch_size):
                                value_dict_list.append(self.proof_queue.pop(0))
                    if len(value_dict_list) > 0:
                        self.prover.batch_prove_amortized(value_dict_list)    
                    time.sleep(self.batch_wait_time)
            else:
                while True:
                    value_dict_list = []
                    with self.cv:
                        while len(self.proof_queue) > 0:
                            value_dict_list.append(self.proof_queue.pop(0))
                    for value_dict in value_dict_list:
                        self.prover.batch_prove_amortized([value_dict])

    def generate_proof(self, value_dict):
        with self.cv:
            value_dict['start_time'] = time.time()
            self.proof_queue.append(value_dict)

    def __init__(self, MIDDLEBOX_ACTIVE, should_batch, batch_wait_time, should_precompute, key, nonce):
        self.proof_queue = []
        self.cv = threading.Condition()
        prover = RegexProver(MIDDLEBOX_ACTIVE, should_precompute, key, nonce)
        a = self.ProverThread(self.cv, self.proof_queue, prover, should_batch, batch_wait_time)
        a.start()