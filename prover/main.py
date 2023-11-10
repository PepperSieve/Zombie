from proxy.dot_chacha import DotChaChaProxy
from proxy.predict_tls_message import test
from benchmark import benchmark
import asyncio, traceback, logging, sys

HOST, PORT = "10.0.0.1", 8080
doh_proof_api = f"http://{HOST}:{PORT}/doh_proof"
co_proof_api  = f"http://{HOST}:{PORT}/co_proof"
dot_proof_api = f"http://{HOST}:{PORT}/dot_chacha_proof"
no_privacy_api = f"http://{HOST}:{PORT}/send_key_iv"
logging.basicConfig(level=logging.DEBUG)

class DNSServerProtocol:
    # initialize connection and send channel opening proof
    def __init__(self):
        MIDDLEBOX_ACTIVE = False
        NEED_PROOF = False
        self.proxy = DotChaChaProxy("Spartan", NEED_PROOF, MIDDLEBOX_ACTIVE, False)

    def connection_made(self, transport):
        self.transport = transport

    # capture dns request and proxy it to dns server
    def datagram_received(self, data, addr):
        reply = self.proxy.forward_data(data)
        if reply:
            data = reply.pack()
            logging.debug("send reply")
            self.transport.sendto(data, addr)
        else:
            # failed
            pass


async def dnsserver():
    logging.debug("Starting UDP server")
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: DNSServerProtocol(),
        local_addr=('127.0.0.1', 53))
    try:
        await asyncio.sleep(3600)
    finally:
        transport.close()


def dnsserver_main():
    # run this file in the prover folder
    try:
        logging.info("Please make sure HOST address is correct")
        logging.info("Please make sure assignment generation server is running")
        logging.info("Please run configure.sh first")
        logging.info("Please run this file in the prover folder, otherwise behaviour is undefined")
        asyncio.run(dnsserver())
    except Exception as e:
        traceback.print_exc() 


def prover():
    # run this file in the prover folder
    try:
        logging.info("Please make sure HOST address is correct")
        logging.info("Please make sure assignment generation server is running")
        logging.info("Please run configure.sh first")
        logging.info("Please run this file in the prover folder, otherwise behaviour is undefined")
        asyncio.run(dnsserver())
    except Exception as e:
        traceback.print_exc()

if __name__ == '__main__':
    MIDDLEBOX_ACTIVE = True
    SHOULD_PRECOMPUTE = True
    try:
        if sys.argv[-1] == "skip":
            MIDDLEBOX_ACTIVE = False
    except:
        pass
    if sys.argv[1] == 'start_prover':
        prover()
    elif sys.argv[1] == 'benchmark_normal':
        if sys.argv[5] == "true":
            should_batch = True
        else:
            should_batch = False
        DotChaChaProxy("Spartan", True, MIDDLEBOX_ACTIVE, SHOULD_PRECOMPUTE=False, dns_type=sys.argv[2], cipher=sys.argv[3], should_batch = should_batch, traffic_generator="trace")
    elif sys.argv[1] == 'benchmark_precompute':
        DotChaChaProxy("Spartan", True, MIDDLEBOX_ACTIVE, SHOULD_PRECOMPUTE=True, dns_type=sys.argv[2], cipher=sys.argv[3], test_queries = int(sys.argv[4]), traffic_generator="normal")
    elif sys.argv[1] == 'custom':
        SHOULD_PRECOMPUTE = sys.argv[2] == "should_precompute"
        should_batch = sys.argv[3] == "should_batch"
        DotChaChaProxy("Spartan", NEED_PROOF = True, MIDDLEBOX_ACTIVE=MIDDLEBOX_ACTIVE, SHOULD_PRECOMPUTE=SHOULD_PRECOMPUTE, should_batch=should_batch, dns_type=sys.argv[4], cipher=sys.argv[5], traffic_generator=sys.argv[6], test_queries = int(sys.argv[7]), batch_wait_time=float(sys.argv[8]), remote_ip=sys.argv[9], should_send_real=sys.argv[10] == "true")
    elif sys.argv[1] == 'no_middlebox':
        DotChaChaProxy("Spartan", NEED_PROOF = False, MIDDLEBOX_ACTIVE=False, SHOULD_PRECOMPUTE=False, should_batch=False, dns_type=sys.argv[2], cipher=sys.argv[3], traffic_generator=sys.argv[4], test_queries = int(sys.argv[5]), remote_ip=sys.argv[6])
    elif sys.argv[1] == 'tmp':
        test()
    else:
        benchmark()