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
import uuid

HOST, PORT = "192.168.0.1", 8080
dot_proof_api = f"http://{HOST}:{PORT}/amortized_proof"
co_dot_proof_api = f"http://{HOST}:{PORT}/channel_open_proof"
precomp_proof_api = f"http://{HOST}:{PORT}/precompute_proof"
logging.basicConfig(format='%(asctime)s - %(message)s', stream=sys.stdout, level=logging.INFO)
SEND_REAL_PROOF = False

hex_to_u8_arr = lambda arr : [int(arr[i:i+2], 16) for i in range(0, len(arr), 2)]
batch_size = 16

def base64_encode(string):
    """
    Removes any `=` used as padding from the encoded string.
    """
    encoded = base64.urlsafe_b64encode(string).decode('utf-8')
    return encoded.rstrip("=")

def timeit(f):
    def timed(*args, **kw):
        ts = time.time()
        result = f(*args, **kw)
        te = time.time()
        logging.info(f'func:{f.__name__} took: {te-ts} sec')
        return result
    return timed


class MyTimer:
    def __init__(self, file):
        self.queue_dict = {}
        self.file = file
        self.lock = threading.Lock()
    
    def start(self, tag, id):
        with self.lock:
            if tag not in self.queue_dict:
                self.queue_dict[tag] = {id: time.time()}
            else:
                self.queue_dict[tag][id] = time.time()
                
    def end(self, tag, id):
        # with open(self.file, 'a') as f:
        try:
            with self.lock:
                start = self.queue_dict[tag][id]
                del self.queue_dict[tag][id]
            interval = time.time() - start
            return interval
        except Exception as e:
            return f"!!!Error {e}!!!"

class ThreadLogger:
    def __init__(self):
        # clear file
        self.table = []
        self.counter_map = {}
        self.lock = threading.Lock()
        with self.lock:
            with open('thread.log', 'w') as f:
                # create and empty the file
                f.write('')
    
    def log(self, msg, t, counter = None, increase = 1):
        if counter is None:
            counter = t
        padding_dict = {
            'Sender': 1,
            'Prover': 2,
            'Reader': 3,
            'PadGenerator': 4
        }
        if counter in self.counter_map:
            self.counter_map[counter] += increase
        else:
            self.counter_map[counter] = increase
        if increase > 1:
            row = f'{datetime.datetime.now()}' + ' ;;;;; ' * padding_dict[t] + msg + f"::{self.counter_map[counter] - increase + 1}-{self.counter_map[counter]}" + ' ;;;;; ' * (4 - padding_dict[t]) + '\n'
        else:
            row = f'{datetime.datetime.now()}' + ' ;;;;; ' * padding_dict[t] + msg + f"::{self.counter_map[counter]}" + ' ;;;;; ' * (4 - padding_dict[t]) + '\n' 
        logging.info(row)

my_timer = MyTimer('timer.log')
thread_logger = ThreadLogger()


def get_time(time_string):
  time_format = "%H:%M:%S.%f"
  parsed_time = datetime.datetime.strptime(time_string, time_format)
  return parsed_time

def extract_info(input_str):
    time_pattern = r'^(\d{2}:\d{2}:\d{2}.\d+)'
    domain_pattern = r'A\? ([\w\.\-]+)\. '
    time_match = re.search(time_pattern, input_str)
    domain_match = re.search(domain_pattern, input_str)
    if time_match and domain_match:
        return time_match.group(1), domain_match.group(1)
    else:
        return None

class TraceSimulator:
  def __init__(self, file):
    with open(file, 'r') as f:
        text = f.read()
    lines = text.split('\n')
    lines = [line for line in lines if len(line) > 0]
    self.tuple_list = []
    for line in lines:
        res = extract_info(line)
        if res is not None:
            time, domain = res
            self.tuple_list.append([get_time(time), domain])
        else:
            logging.info(line, "extract failed")
    current_time = self.tuple_list[0][0]
    for idx in range(len(self.tuple_list)):
        interval = self.tuple_list[idx][0] - current_time
        current_time = self.tuple_list[idx][0]
        self.tuple_list[idx][0] = interval.total_seconds()
    self.counter = 0
  
  def proceed(self):
    logging.info(f"request number {self.counter}")
    if self.counter == 0:
        # wait for pads to be generated
        time.sleep(3)
    if self.counter < len(self.tuple_list):
      logging.info(f"sleep for {self.tuple_list[self.counter][0]} seconds")
      interval = self.tuple_list[self.counter][0]
      if interval > 3:
        interval = 3 
      time.sleep(interval)
      res = self.tuple_list[self.counter][1]
      self.counter += 1
      return res
    logging.info("Simulation ended.")
    return None

class RandomTraceSimulator:
  def __init__(self, file, num_requests):
    with open(file, 'r') as f:
        text = f.read()
    lines = text.split('\n')
    lines = [line for line in lines if len(line) > 0]
    start_index = random.randint(0, len(lines) - num_requests)
    lines = lines[start_index:start_index + num_requests]
    self.tuple_list = []
    for line in lines:
        res = extract_info(line)
        if res is not None:
            time, domain = res
            self.tuple_list.append([get_time(time), domain])
        else:
            logging.info(line, "extract failed")
    current_time = self.tuple_list[0][0]
    for idx in range(len(self.tuple_list)):
        interval = self.tuple_list[idx][0] - current_time
        current_time = self.tuple_list[idx][0]
        self.tuple_list[idx][0] = interval.total_seconds()
    self.counter = 0
  
  def proceed(self):
    logging.info(f"request number {self.counter}")
    if self.counter == 0:
        # wait for pads to be generated
        time.sleep(random.uniform(1.5, 4.5))
    if self.counter < len(self.tuple_list):
      logging.info(f"sleep for {self.tuple_list[self.counter][0]} seconds")
      interval = self.tuple_list[self.counter][0]
      if interval > 3:
        interval = 3 
      time.sleep(interval)
      res = self.tuple_list[self.counter][1]
      self.counter += 1
      return res
    logging.info("Simulation ended.")
    return None

class DotChaChaProxy:
    def __init__(self, backend, NEED_PROOF, MIDDLEBOX_ACTIVE, SHOULD_PRECOMPUTE, dns_type = 'Dot', cipher = 'ChaCha', test_queries = 0, should_batch = True, traffic_generator = "trace", batch_wait_time=0.1, remote_ip='8.8.8.8', should_send_real=True):
        global SEND_REAL_PROOF
        SEND_REAL_PROOF = should_send_real
        start_time = time.time()
        SHOULD_CO = True
        if NEED_PROOF:
            if MIDDLEBOX_ACTIVE:
                try:
                    requests.post(dot_proof_api + '/test', json={'test': 'test'})
                except:
                    print("not implemented")
                    # raise NotImplementedError
        tls_timer = time.time()
        server_socket = socket(AF_INET, SOCK_STREAM)
        server_socket.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
        self.dns_type = dns_type
        logging.info(f"Will connect {remote_ip}")
        if dns_type == 'Dot':
            server_socket.connect((remote_ip, 853))
        elif dns_type == 'Doh':
            server_socket.connect(('8.8.8.8', 443)) 
        elif dns_type == 'Regex':
            # example.com
            server_socket.connect((remote_ip, 853)) 
            # server_socket.connect(('8.8.8.8', 443)) 
        else:
            raise NotImplemented
        server_connection = TLSConnection(server_socket)
        settings = HandshakeSettings()
        settings.versions = [(3, 4)]
        if cipher == 'ChaCha':
            settings.cipherNames = ["chacha20-poly1305"]
        elif cipher == 'AES':
            settings.cipherNames = ["aes128gcm"]
        else:
            settings.cipherNames = ["chacha20-poly1305"]
        settings.eccCurves = ["secp256r1"]
        settings.keyShares = ["secp256r1"]
        self.server_connection = server_connection
        self.SN = 0
        self.NEED_PROOF = NEED_PROOF
        self.MIDDLEBOX_ACTIVE = MIDDLEBOX_ACTIVE
        logging.info("Will handshake")
        server_connection.handshakeClientCert(settings=settings, print_handshake=False)
        logging.info(f"Set up tcp takes {time.time() - tls_timer} sec")
        logging.info(f"Cipher suite: {server_connection.session.getCipherName()}")
        # keep connection
        # self.send_sample_request("example.com", False)
        t0 = time.time()
        if NEED_PROOF:
            t1 = time.time()
            self.c_ap_key = self.server_connection._recordLayer._writeState.encContext.key.hex()
            self.c_ap_iv = self.server_connection._recordLayer._writeState.fixedNonce.hex()
            if SHOULD_CO:
                co_prover = DotChannelOpenProver(backend, cipher)
                t2 = time.time()
                logging.info(f"Get DotChannelOpenProver takes {t2 - t1} seconds")
                # logging.info(co_prover.generate_witness({'conn': self.server_connection}))
                proof = co_prover.generate_proof({'conn': self.server_connection})
                t3 = time.time()
                logging.info(f"Generate CO proof takes {t3 - t2} seconds")
                if self.MIDDLEBOX_ACTIVE:
                    json_proof = {
                        'comm': co_prover.get_comm(self.c_ap_key, self.c_ap_iv),
                        'r1cs_proof': proof.hex()
                    }
                    requests.post(co_dot_proof_api, json=json_proof)
                t4 = time.time()
                logging.info(f"Wait for middlebox verify CO takes {t4 - t3} seconds")
            t4 = time.time()
            if dns_type == "Regex":
                self.regex_prover = RegexAsyncProver(MIDDLEBOX_ACTIVE, should_batch, batch_wait_time, SHOULD_PRECOMPUTE, self.c_ap_key, self.c_ap_iv)
            else:
                batch_size = -1
                if traffic_generator == 'poisson':
                    batch_size = test_queries
                self.dns_prover = DotChaChaAsyncProver(cipher, dns_type, MIDDLEBOX_ACTIVE, SHOULD_PRECOMPUTE, self.c_ap_key, self.c_ap_iv, should_batch, batch_wait_time, self.server_connection, False, batch_size)
            t5 = time.time()
            logging.info(f"Get Async Prover takes {t5 - t4} seconds")
            logging.info(f"channel opening takes {t5 - t0:.03f} seconds")
        read_queue = Queue(maxsize=0)
        self.read_queue = read_queue
        read_thread = threading.Thread(target=self.read_connection)
        read_thread.start()
        # TODO: rename these generators later
        if traffic_generator == "trace":
            sim = TraceSimulator('dnslog_500')
            while True:
                res = sim.proceed()
                if res == None:
                    break
                self.send_sample_request(res, dns_type, NEED_PROOF)
        elif traffic_generator == "random_trace":
            sim = RandomTraceSimulator('dnslog_all', test_queries)
            while True:
                res = sim.proceed()
                if res == None:
                    break
                self.send_sample_request(res, dns_type, NEED_PROOF)
        elif traffic_generator == "normal":
            for num in range(1, test_queries + 1):
                logging.info(f"request number {num}")
                self.send_sample_request("amazon.com", dns_type, NEED_PROOF)
                if num in [10, 50, 100, 500]:
                    t2 = time.time()
                    with open(f'{dns_type}{cipher}.log', 'a') as f:
                        logging.info(f"send {num} queries takes {t2 - t1:.03f}")
                        f.write(f"send {num} queries takes {t2 - t1:.03f}\n")
            with open(f'{dns_type}{cipher}.log', 'a') as f:
                t2 = time.time()
                logging.info(f"send {test_queries} queries takes {t2 - t1:.03f}")
                f.write(f"send {test_queries} queries takes {t2 - t1:.03f}")
            with open(f'{dns_type}{cipher}.log', 'r') as f:
                logging.info(f.read())
        elif traffic_generator == "poisson":
            # sleep 10 seconds to make sure setup has finished
            elapsed = time.time() - start_time
            if elapsed > 30:
                logging.warn(f"Setup takes {elapsed} s, too long!!!!")
            else:
                logging.warn(f"Setup takes {elapsed} s, will wait till 10 seconds")
            while time.time() - start_time < 10:
                time.sleep(0.05)
            while True:
                avg_batch_size = test_queries
                avg_interval = avg_batch_size / 32
                logging.info(f"Avg interval is {avg_interval}")
                batch_size = avg_batch_size
                t1 = time.time()
                logging.info(f"generated batch size is {batch_size}")
                for _ in range(batch_size):
                    self.send_sample_request("amazon.com", dns_type, NEED_PROOF)
                # make it a decimal
                interval = np.random.exponential(avg_interval)
                logging.info(f"will wait for {interval}")
                time.sleep(interval)
        elif traffic_generator == "constant":
            # sleep 10 seconds to make sure setup has finished
            elapsed = time.time() - start_time
            if elapsed > 30:
                logging.warn(f"Setup takes {elapsed} s, too long!!!!")
            else:
                logging.warn(f"Setup takes {elapsed} s, will wait till 10 seconds")
            while time.time() - start_time < 10:
                time.sleep(0.05)
            while True:
                self.send_sample_request("amazon.com", dns_type, NEED_PROOF)    
                time.sleep(5)
        read_thread.join()

    def read_connection(self):
        while True:
            logging.info("before read response")
            # will data race happen here?
            first_response = self.server_connection.read()
            t = datetime.datetime.now()
            # signal that has got the response
            # self.read_queue.put(time.time())
            try:
                dns_response = DNSRecord.parse(first_response[2:])
                interval = my_timer.end('dns_request', dns_response.header.id)
                logging.info(f"Receive response takes {interval} id:{dns_response.header.id}, time is {t}...")
            except Exception as e:
                interval = my_timer.end('dns_request', first_response.decode())
                logging.info(f"Receive response takes {interval} regex")
                # thread_logger.log(f"Receive response takes {interval} id:{dns_response.header.id}", "Reader")

    def send_sample_request(self, domain, dns_type, TEST_PROVE):
        logging.info("send sample request")
        # logging.info(f"will send sample request {domain}")
        # TODO: send after the proof
        if dns_type == 'Dot':
            record = DNSRecord.question(domain, "A")
            id = record.header.id
            data = record.pack()
            data_len_hex = hex(len(data))[2:]
            prefix_hex = '0' * (4 - len(data_len_hex)) + data_len_hex
            message_hex = prefix_hex + data.hex()
            message = bytearray.fromhex(message_hex)
        elif dns_type == 'Doh':
            # TODO: this doesn't work now
            data = DNSRecord.question(domain,"A").pack()
            b64_dnsq = base64_encode(data)
            doh_request = f"GET /dns-query?dns={b64_dnsq} HTTP/1.1\r\nHost: 1.1.1.1\r\nAccept-Encoding: identity\r\nAccept: application/dns-message\r\n\r\n"
            message = doh_request.encode('utf-8')
        elif dns_type == 'Regex':
            uuid_string = str(uuid.uuid4())
            # https_request = f"""POST / HTTP/1.1\r\nHost: www.google.com\r\nContent-Type: application/json\r\nContent-Length: 20\r\n\r\n{uuid_string}\r\n"""
            https_request = f"""{uuid_string}"""
            id = https_request
            message = https_request.encode('utf-8')
            logging.info(f"Will send message {message}")
            self.server_connection.write(message)
        else:
            raise NotImplementedError
        my_timer.start('dns_request', id)
        if TEST_PROVE:
            self.prove_dns(domain, message)
        else:
            if dns_type == 'Dot':
                self.server_connection.write(message)
        self.SN += 1

    def prove_dns(self, domain, message):
        ciphertexts = self.server_connection._recordLayer.ciphertextMessage
        ciphertext = ciphertexts[-1].write()
        packet_id = ciphertext[:10]
        if self.dns_type == 'Regex':
            self.regex_prover.generate_proof({'ciphertext': [int(b) for b in ciphertext], 'SN': self.SN, 'key': self.c_ap_key, 'iv': self.c_ap_iv})
        else:
            self.dns_prover.generate_proof({'message': message, 'dot_ct': ciphertext.hex(), 'SN': self.SN, 'domain': domain, 'key': self.c_ap_key, 'iv': self.c_ap_iv, 'packet_id': packet_id})

    @timeit
    def forward_data(self, data):
        data_len_hex = hex(len(data))[2:]
        prefix_hex = '0' * (4 - len(data_len_hex)) + data_len_hex
        message_hex = prefix_hex + data.hex()
        message = bytearray.fromhex(message_hex)
        self.server_connection.write(message)
        request = DNSRecord.parse(data)
        domain = '.'.join(
            list(map(lambda x: x.decode('utf-8'), request.questions[0].qname.label)))
        if self.NEED_PROOF:
            self.prove_dns(domain)
        self.SN += 1
        logging.info("will read")
        # if this block, the whole program will block and no packet will be processed
        # set a timeout for this
        server_response = self.server_connection.read()
        reply = DNSRecord.parse(server_response[2:])
        # logging.info("read finish", server_response)
        # if len(server_response) <= 2 or server_response[-2] != b'':
        #     return None
        # else:
        #     body = server_response[-1]
        #     reply = DNSRecord.parse(body)
        return reply

def get_cstr(str):
    return ctypes.c_char_p(str.encode())

def get_pad(key: str, iv: str, seq_num: int) -> bytes:
    key = bytes.fromhex(key)
    iv = bytes.fromhex(iv)
    cip = ChaCha20Poly1305(key)
    iv = (int(bytes(iv).hex(), 16) ^ seq_num).to_bytes(12, byteorder='big')
    pad = cip.encrypt(iv, b'\x00' * 255)[:255]
    return pad

def chacha_encrypt(key: str, iv: str, seq_num: int, message) -> bytes:
    key = bytes.fromhex(key)
    iv = bytes.fromhex(iv)
    cip = ChaCha20Poly1305(key)
    iv = (int(bytes(iv).hex(), 16) ^ seq_num).to_bytes(12, byteorder='big')
    pad = cip.encrypt(iv, message)[:255]
    result = [int(b) for b in pad]
    logging.info(f"ChaCha before encrypted is {message}")
    logging.info(f"ChaCha encrypted is {pad}")
    return result

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

def get_pad_comm(pad: bytes, hash_generator):
    pad += b'\x00' * (9 * 31 - 255)
    pad_comm = 0
    for idx in range(9):
        pad_comm = hash_generator.poseidon_hash([pad_comm, int(pad[idx * 31: idx * 31 + 31].hex(), 16)])
    return str(pad_comm)

class DotChaChaProver:
    def __init__(self, cipher, dns_type, MIDDLEBOX_ACTIVE, enable_precomp, key, nonce, server_connection, send_after_proof):
        self.merkel_generator = MerkelWitnessGenerator("/mydata/dalek_blocklist_wildcard_sorted.npy", "/mydata/merkle_tree_structure.npy")
        self.hash_generator = PoseidonHashGenerator('dalek')
        self.enable_precomp = enable_precomp
        self.MIDDLEBOX_ACTIVE = MIDDLEBOX_ACTIVE
        self.circuit = dns_type + cipher
        self.seq_num = 0
        self.server_connection = server_connection
        self.send_after_proof = send_after_proof
        if enable_precomp:
            circuit_name = self.circuit + 'AmortizedUnpack'
        else:
            circuit_name = self.circuit + 'Amortized'
        self.prover = zkmb_get_prover(circuit_name)
        if enable_precomp:
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
            thread_logger.log(f"Precomp {len(prover_witnesses)} takes {t2 - t1:.03f}", "PadGenerator")
            # calculate pad_comm
            if self.MIDDLEBOX_ACTIVE:
                json_proof = {"r1cs_proof": proof.hex(), "comm_list": comm_list, "pad_comm_list": pad_comm_list, "seq_num_list": seq_num_list}
                response = requests.post(precomp_proof_api, json=json_proof)
            thread_logger.log(f"Precomp response", "PadGenerator")
            logging.info(f"seq num proved {pad_seq_num.value}")
            pad_seq_num.value += batch_size

    def batch_prove_amortized(self, value_dict_list: List[Dict]):
        thread_logger.log(f"Will batch_prove_amortized", "Prover")
        t1 = time.time()
        witness_list = self.generate_witness_list(value_dict_list, self.enable_precomp)
        logging.info("Got witness list")
        t2 = time.time()
        thread_logger.log(f"Finish generating witness takes {t2 - t1}", "Prover")
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
            proof = zkmb_prove(self.circuit + 'AmortizedUnpack', self.prover, witness_list)
            p.nice(current_priority)
        else:
            t3 = time.time()
            logging.info(f"proof size {30176 * len(value_dict_list)}")
            if SEND_REAL_PROOF:
                logging.info("Send real proof")
                proof = zkmb_prove(self.circuit + 'Amortized', self.prover, witness_list)
            else:
                logging.info("Send fake proof")
                proof = b'0' * 30176 * len(value_dict_list)
        t4 = time.time()
        thread_logger.log(f"Batch generating {len(value_dict_list)} proofs takes {t4 - value_dict_list[0]['start_time']:0.3f} seconds", "Prover", "batch_counter", len(value_dict_list))
        if self.MIDDLEBOX_ACTIVE:
            threading.Thread(target=self.send_proof, args=(value_dict_list, proof)).start()

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
            t2 = time.time()
            logging.info(f"Send proof of batch size {batch_end - batch_start + 1} takes {t2 - t1} sec")
        except Exception as e:
            logging.info(e)
        if self.send_after_proof:
            for value_dict in value_dict_list:
                self.server_connection.write(value_dict['message'])
                ciphertexts = self.server_connection._recordLayer.ciphertextMessage
                ciphertext = ciphertexts[-1].write()
                logging.info(f"Actual ciphertext send is {[int(b) for b in ciphertext]}")
                # plaintext = chacha_encrypt(value_dict['key'], value_dict['iv'], value_dict['SN'], ciphertext)
                # logging.info(f"Decrypted plaintext sent is {bytes(plaintext)}")

    def generate_single_witness(self, value_dict, enable_precomp):
        key = value_dict['key']
        iv = value_dict['iv']
        dot_ct = value_dict['dot_ct']
        domain = value_dict['domain']
        SN = value_dict['SN']
        comm = hex(self.hash_generator.poseidon_hash([int(key, 16), int(iv, 16)]))[2:]
        t1 = time.time()
        merkel_witness = self.merkel_generator.generate(domain)
        t2 = time.time()
        logging.info("Before chacha encrypt message")
        witness = {
            "dns_ct": chacha_seal(key, iv, SN, value_dict['message']),
            "SN": SN
        }
        logging.info(f"Predicted ciphertext for SN {SN} is {witness['dns_ct']}")
        if enable_precomp:
            pad = get_pad(key, iv, SN)
            pad_comm = get_pad_comm(pad, self.hash_generator)
            witness['pad'] = hex_to_u8_arr(pad.hex())
            witness['comm_pad'] = pad_comm
            logging.info(f"precomputed witness {witness['comm_pad']} {witness['dns_ct']}")
        else:
            witness["comm"] = str(int(comm, 16))
            witness["key"] = hex_to_u8_arr(key)
            witness["nonce"] = hex_to_u8_arr(iv)
        for k, v in merkel_witness.items():
            witness[k] = v
        return witness


    def generate_witness_list(self, value_dict_list, enable_precomp: bool) -> str:
        logging.info("Enter generate witness list")
        witness_list = []
        for value_dict in value_dict_list:
            logging.info("enter value_dict iter")
            witness_list.append(self.generate_single_witness(value_dict, enable_precomp))
            logging.info("end value_dict iter")
        logging.info("End generate witness list")
        # logging.info(f"witness list is {witness_list}")
        return json.dumps(witness_list)

class DotChaChaAsyncProver:
    class ProverThread(threading.Thread):
        def __init__(self, cv: threading.Condition, proof_queue: List, prover: DotChaChaProver, should_batch: bool, batch_wait_time: float, batch_size):
            self.cv = cv
            self.proof_queue = proof_queue
            self.prover = prover
            self.should_batch = should_batch
            self.batch_wait_time = batch_wait_time
            self.batch_size = batch_size
            super().__init__()

        def run(self):
            logging.info("start running")
            if self.should_batch:
                logging.info("Should batch")
                while True:
                    value_dict_list = []
                    with self.cv:
                        while len(self.proof_queue) < self.batch_size:
                            self.cv.wait()
                        # TODO: this is not tested
                        if self.batch_size == -1:
                            for _ in range(len(self.proof_queue)):
                                value_dict_list.append(self.proof_queue.pop(0))
                        else:
                            if len(self.proof_queue) >= self.batch_size:
                                logging.info(f"my batch size is {self.batch_size}")
                                for _ in range(self.batch_size):
                                    value_dict_list.append(self.proof_queue.pop(0))
                    if len(value_dict_list) > 0:
                        self.prover.batch_prove_amortized(value_dict_list)    
            else:
                logging.info("No batch")
                while True:
                    value_dict_list = []
                    with self.cv:
                        while len(self.proof_queue) == 0:
                            self.cv.wait()
                        while len(self.proof_queue) > 0:
                            value_dict_list.append(self.proof_queue.pop(0))
                    for value_dict in value_dict_list:
                        self.prover.batch_prove_amortized([value_dict])

    def generate_proof(self, value_dict):
        if not self.send_after_proof:
            logging.info("Will write message")
            self.server_connection.write(value_dict['message'])
        with self.cv:
            value_dict['start_time'] = time.time()
            self.proof_queue.append(value_dict)
            self.cv.notify()

    def __init__(self, cipher, dns_type, MIDDLEBOX_ACTIVE, enable_precomp, key, iv, should_batch, batch_wait_time, server_connection, send_after_proof, batch_size):
        self.proof_queue = []
        self.cv = threading.Condition()
        self.send_after_proof = send_after_proof
        self.server_connection = server_connection
        prover = DotChaChaProver(cipher, dns_type, MIDDLEBOX_ACTIVE, enable_precomp, key, iv, server_connection, send_after_proof)
        a = self.ProverThread(self.cv, self.proof_queue, prover, should_batch, batch_wait_time, batch_size)
        a.start()

def str_to_u8_arr(s: str) -> List[int]:
    return [int(s[i:i+2], 16) for i in range(0, len(s), 2)]

def str_to_u32_arr(s: str) -> List[int]: 
    return [int(s[i:i+8], 16) for i in range(0, len(s), 8)]

def get_tail_minus_36(line: str) -> List[int]:
    line_len = len(line) / 2
    num_whole_blocks = (line_len - 36) // 64
    tail_len = line_len - num_whole_blocks * 64
    s = line[int(len(line) - tail_len * 2):]
    return str_to_u8_arr(s)

class DotChannelOpenProver(CircuitProver):
    def __init__(self, backend, cipher):
        self.hash_generator = PoseidonHashGenerator('dalek')
        cipher_map = {'AES': 'aes128gcm', 'ChaCha': 'chacha20-poly1305'}
        self.hs_generator = HandshakeInfoGenerator('dalek', cipher_map[cipher])
        self.circuit = cipher + 'ChannelOpen'
        if self.circuit in ['ChaChaChannelOpen', 'AESChannelOpen']:
            self.prover = zkmb_get_prover(self.circuit)

    def get_comm(self, key, iv) -> str:
        return str(self.hash_generator.poseidon_hash([int(key, 16), int(iv, 16)]))

    @timeit
    def generate_proof(self, value_dict):
        witness = self.generate_witness(value_dict)
        return zkmb_prove(self.circuit, self.prover, witness)
    
    @timeit
    def generate_witness(self, value_dict: dict) -> str:
        hs_dict = self.hs_generator.get_handshake_info(value_dict['conn'])
        HS: List[int] = str_to_u8_arr(hs_dict["HS"])
        H2: List[int] = str_to_u8_arr(hs_dict["H_2"])
        ServExt_ct_tail: List[int] = get_tail_minus_36(hs_dict["ch_sh"] + hs_dict["ct_3"])
        SHA_H_Checkpoint: List[int] = str_to_u32_arr(hs_dict["H_state_tr7"])
        ServExt_len: int = len(hs_dict["ct_3"]) // 2
        ServExt_tail_len: int = len(ServExt_ct_tail)
        CH_SH_len: int = len(hs_dict["ch_sh"]) // 2
        ServExt_ct_len: int = len(hs_dict["ct_3"]) // 2
        comm: str = str(self.hash_generator.poseidon_hash([int(hs_dict['c_ap_key'], 16), int(hs_dict['c_ap_iv'], 16)]))
        witness: Dict[str, Any] = {
            'HS': HS,
            'H2': H2, 
            'ServExt_len': ServExt_len,
            'ServExt_ct_tail': ServExt_ct_tail,
            'SHA_H_Checkpoint': SHA_H_Checkpoint,
            'ServExt_tail_len': ServExt_tail_len,
            'CH_SH_len': CH_SH_len,
            'ServExt_ct_len': ServExt_ct_len,
            'comm': comm
        }
        logging.info("channel open: " + json.dumps(witness))
        return json.dumps([witness])


if __name__ == '__main__':
    if sys.argv[1] == 'with_middlebox':
        DotChaChaProxy("Spartan", True, True)
    elif sys.argv[1] == 'skip_middlebox':
        DotChaChaProxy("Spartan", True, False)
    # DotChaChaProxy("Groth16", True, True)