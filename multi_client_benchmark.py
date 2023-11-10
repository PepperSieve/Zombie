import os, sys, threading, subprocess, re, time, json
import numpy as np
from datetime import datetime
import numpy

middlebox_addr = "collinz@ms0628.utah.cloudlab.us"
client_addrs = """collinz@ms0612.utah.cloudlab.us
collinz@ms0634.utah.cloudlab.us
collinz@ms0632.utah.cloudlab.us
collinz@ms0644.utah.cloudlab.us
collinz@ms0643.utah.cloudlab.us
collinz@ms0601.utah.cloudlab.us
collinz@ms0637.utah.cloudlab.us
collinz@ms0624.utah.cloudlab.us
collinz@ms0636.utah.cloudlab.us
collinz@ms0626.utah.cloudlab.us
collinz@ms0607.utah.cloudlab.us
collinz@ms0631.utah.cloudlab.us
collinz@ms0619.utah.cloudlab.us
collinz@ms0627.utah.cloudlab.us
collinz@ms0630.utah.cloudlab.us
collinz@ms0623.utah.cloudlab.us
collinz@ms0614.utah.cloudlab.us
collinz@ms0621.utah.cloudlab.us"""
first_client = "collinz@ms0612.utah.cloudlab.us"
tlsserver_addr = "collinz@ms0641.utah.cloudlab.us"
# this has to be ip instead of domain name cause we have to configure ip route rules for the client
remote_ip = "128.110.216.232"

CLOUDLAB_MACHINE = 'M400'

dir_path = os.path.dirname(os.path.realpath(__file__))

WAIT_MIDDLEBOX = 10
EXPERIMENT_TIME = 120
REPO_ADDR = "https://github.com/collinzrj/Zombie.git"

class Client:
    def __init__(self, addr, log_file):
        self.addr = addr
        self.f = open(log_file, 'w')

    def run(self, cmd):
        subprocess.run(['ssh', '-o', 'StrictHostKeyChecking=no', self.addr, cmd], stdout=self.f, stderr=self.f)
    
    def kill(self):
        cmd = "ps -aux | grep python; sudo pkill -9 -f python;"
        self.run(cmd)
    
    def run_experiment(self, should_precompute, batch_size, wait_time = 0.1, remote_ip = '8.8.8.8', should_send_real = "true", protocol="Dot"):
        num_requests = 50
        batch_wait_time = 0.1
        cmd = f"""cd ~/Zombie/prover;
        sudo rm ~/Zombie/circ/target/release/libcirc_zkmb_*;"""
        if should_precompute:
            pre = "should_precompute"
        else:
            pre = "no_precompute"
        b = f"sudo ip r add {remote_ip} via 192.168.0.1; sudo /usr/bin/time -v timeout {EXPERIMENT_TIME}s ./venv/bin/python main.py custom {pre} should_batch {protocol} ChaCha poisson {batch_size} {wait_time} {remote_ip} {should_send_real}"
        self.run(cmd + b)

    def run_experiment_cmd(self, b):
        cmd = f"""cd ~/Zombie/prover;
        sudo rm ~/Zombie/circ/target/release/libcirc_zkmb_*;"""
        self.run(cmd + b)

    def retrieve_thread_log(self, file):
        cmd = 'cd ~/Zombie/prover; cat thread.log'
        with open(file, 'w') as f:
            subprocess.run(['ssh', self.addr, cmd], stdout=f, stderr=f)
        with open(f'formated_{file}', 'w') as f:
            subprocess.run(['column', '-t', '-s', "','", file], stdout=f, stderr=f)
    
    def no_policy_experiment(self, batch_size):
        cmd = f"""cd ~/Zombie/prover;
        sudo rm ~/Zombie/circ/target/release/libcirc_zkmb_*;"""
        b = f"sudo /usr/bin/time -v timeout {EXPERIMENT_TIME}s ./venv/bin/python main.py no_middlebox Dot ChaCha poisson {batch_size}"
        self.run(cmd + b)

    def prepare(self):
        cmd = f"""sudo rm -rf Zombie;
        git config --global credential.helper store;
        git clone --recursive {REPO_ADDR};
        cd ~/Zombie/prover; ./configure.sh;"""
        self.run(cmd)

    def update_git(self):
        cmd = f"""cd ~/Zombie/prover; git pull;"""
        self.run(cmd)

class RemoteTLSServer:
    def __init__(self, addr) -> None:
        self.addr = addr
        self.stdout = open('tlsserver_stdout.log', 'w')
        self.stderr = open('tlsserver_stderr.log', 'w')

    def prepare(self):
        cmd = f"""git clone --recursive {REPO_ADDR};
        cp ~/Zombie/tlsserver/tlsserver.py .;
        cp ~/Zombie/tlsserver/csr_defaults.cnf .;
        sudo apt-get install openssl;
        openssl genpkey -algorithm RSA -out key.pem;
        openssl req -new -key key.pem -out csr.pem -config csr_defaults.cnf
        openssl x509 -req -days 365 -in csr.pem -signkey key.pem -out cert.pem;
        """
        subprocess.run(['ssh', '-o', 'StrictHostKeyChecking=no', self.addr, cmd], stdout=self.stdout, stderr=self.stderr)

    def restart(self):
        cmd = f"sudo pkill -9 python; cd /users/collinz; sudo timeout {EXPERIMENT_TIME + WAIT_MIDDLEBOX}s python3 tlsserver.py;"
        subprocess.run(['ssh', '-o', 'StrictHostKeyChecking=no', self.addr, cmd], stdout=self.stdout, stderr=self.stderr)

class Middlebox:
    def __init__(self, addr) -> None:
        self.addr = addr
        self.stdout = open('middlebox_stdout.log', 'w')
        self.stderr = open('middlebox_stderr.log', 'w')
        # self.cores_cmd = 'taskset -c 0,1,2,3,4,5,6,7' 
        self.cores_cmd = '' 

    def run(self, cmd):
        subprocess.run(['ssh', '-o', 'StrictHostKeyChecking=no', self.addr, cmd], stdout=self.stdout, stderr=self.stderr)

    def prepare(self):
        cmd = f"""rm -rf Zombie;
        git config --global credential.helper store;
        git clone --recursive {REPO_ADDR};
        cd ~/Zombie/middlebox; ./configure.sh;"""
        self.run(cmd)

    def async_experiment(self, protocol, should_verify_co, batch_size):
        self.update_git()
        cmd = f"""sudo pkill -9 middlebox;
        cd ~/Zombie/middlebox;
        sudo ./iptables_configure.sh {CLOUDLAB_MACHINE} async;
        sudo /usr/bin/time -v {self.cores_cmd} timeout {EXPERIMENT_TIME + WAIT_MIDDLEBOX}s ./target/release/middlebox benchmark_async {protocol} ChaCha 10 {should_verify_co} {batch_size};
        """
        self.run(cmd)
    
    def sync_experiment(self, protocol, should_verify_co):
        self.update_git()
        cmd = f"""sudo pkill -9 middlebox;
        cd ~/Zombie/middlebox;
        sudo ./iptables_configure.sh {CLOUDLAB_MACHINE} async;
        sudo /usr/bin/time -v {self.cores_cmd} timeout {EXPERIMENT_TIME + WAIT_MIDDLEBOX}s ./target/release/middlebox benchmark_sync {protocol} ChaCha 10 {should_verify_co};
        """
        self.run(cmd)
    
    def no_policy_experiment(self):
        cmd = f"""sudo pkill -9 middlebox;
        cd ~/Zombie/middlebox;
        sudo ./iptables_configure.sh {CLOUDLAB_MACHINE} async;
        sudo /usr/bin/time -v timeout {EXPERIMENT_TIME + WAIT_MIDDLEBOX}s ./target/release/middlebox no_policy;
        """
        self.run(cmd)
    
    def no_privacy_experiment(self):
        self.update_git()
        cmd = f"""sudo pkill -9 middlebox;
        cd ~/Zombie/middlebox;
        sudo ./iptables_configure.sh {CLOUDLAB_MACHINE} async;
        sudo /usr/bin/time -v timeout {EXPERIMENT_TIME + WAIT_MIDDLEBOX}s ./target/release/middlebox no_privacy;
        """
        self.run(cmd)
    
    def congestion_control_experiment(self, batch_size):
        self.update_git()
        cmd = f"""sudo pkill -9 middlebox;
        cd ~/Zombie/middlebox;
        sudo ./iptables_configure.sh {CLOUDLAB_MACHINE} async;
        sudo /usr/bin/time -v timeout {EXPERIMENT_TIME + WAIT_MIDDLEBOX}s ./target/release/middlebox test_congestion {batch_size};
        """
        self.run(cmd)

    def batch_self_benchmark_experiment(self, batch_size, num_clients):
        self.update_git()
        cmd = f"""sudo pkill -9 middlebox;
        cd ~/Zombie/middlebox;
        sudo ./iptables_configure.sh {CLOUDLAB_MACHINE} async;
        sudo /usr/bin/time -v {self.cores_cmd} timeout {EXPERIMENT_TIME + WAIT_MIDDLEBOX}s ./target/release/middlebox batch_benchmark {batch_size} {num_clients};
        """
        self.run(cmd)
    
    def update_git(self):
        # cmd = f"""cd ~/Zombie/middlebox; git pull --recurse-submodules; $HOME/.cargo/bin/cargo build --release;"""
        cmd = f"""cd ~/Zombie/middlebox; git pull;"""
        self.run(cmd)

# def client_run(addr, log_file, batch_size):
#     client = Client(addr, log_file)
#     if sys.argv[1] == 'retrieve':
#         client.retrieve_thread_log(f'thread_{log_file}')
#     elif sys.argv[1] == 'run':
#         client.git_change_remote()
#         client.kill()
#         client.run_experiment(batch_size)
#         # client.kill()
#     elif sys.argv[1] == 'kill':
#         client.kill()
#     elif sys.argv[1] == 'git':
#         client.git_change_remote()

def client_cleanup(addr, log_file):
    client = Client(addr, log_file)
    client.update_git()
    client.kill()


def middlebox_run(addr, mode, protocol, should_verify_co, batch_size=0):
    middlebox = Middlebox(addr)
    if mode == 'async':
        middlebox.async_experiment(protocol, should_verify_co, batch_size)
    elif mode == 'sync':
        middlebox.sync_experiment(protocol, should_verify_co)
    elif mode == 'no_policy':
        middlebox.no_policy_experiment()
    elif mode == 'test_congestion':
        middlebox.congestion_control_experiment(batch_size)
    elif mode == 'no_privacy':
        middlebox.no_privacy_experiment()

def scalability_experiment_avg(current_time, num_clients, mode, batch_size, times, remote_ip, protocol):
    for idx in range(times):
        scalability_experiment(current_time, num_clients, mode, batch_size, idx, remote_ip, protocol)


def scalability_experiment(current_time, num_clients, mode, batch_size, idx, remote_ip, protocol):
    kill_threads = []
    # TODO: kill all here
    for line in list(client_addrs.split('\n')):
        addr = line.split(' ')[0]
        t = threading.Thread(target=client_cleanup, args=(addr, 'kill.log'))
        t.start()
        kill_threads.append(t)
    for t in kill_threads:
        t.join()
    print("All clients prepared")
    threads = []
    print(f"Start experiment {mode} {num_clients} {batch_size}")
    os.chdir(os.path.join(dir_path, 'log'))
    try:
        os.mkdir(current_time)
    except:
        pass
    os.chdir(current_time)
    directory_name = f"scalability_{mode}_{num_clients}_{batch_size}_num_{idx}_LENGTH_{EXPERIMENT_TIME}s"
    os.mkdir(directory_name)
    os.chdir(directory_name)
    t = threading.Thread(target=middlebox_run, args=(middlebox_addr, mode, protocol, "false", batch_size))
    t.start()
    threads.append(t)
    remote_tlsserver = RemoteTLSServer(tlsserver_addr)
    t = threading.Thread(target=remote_tlsserver.restart)
    t.start()
    threads.append(t)
    time.sleep(WAIT_MIDDLEBOX)
    i = 0
    def client_run(addr, log_file, should_precompute, batch_size, remote_ip):
        client = Client(addr, log_file)
        client.run_experiment(should_precompute, batch_size, wait_time = 0.01, remote_ip=remote_ip, should_send_real="false", protocol=protocol)
    for line in list(client_addrs.split('\n'))[0:num_clients]:
        i += 1
        addr = line.split(' ')[0]
        log_file = f"client_{i}.log"
        if mode == 'sync':
            should_precompute = True
        else:
            should_precompute = False
        t = threading.Thread(target=client_run, args=(addr, log_file, should_precompute, batch_size, remote_ip))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    scalability_analyze(num_clients, batch_size, EXPERIMENT_TIME)

def regex_analysis():
    output = {}
    with open('client.log', 'r') as f:
        log = f.read()
        pattern = r"Receive response takes ([\d.]+.[\d.]+)"
        matches = re.findall(pattern, log)
        response_times = [float(time) for time in matches]
        pattern = r"Batch generating ([\d.]+) proofs takes ([\d.]+.[\d.]+)"
        matches = re.findall(pattern, log)
    response_variance = numpy.var(response_times)
    avg_response_time = sum(response_times) / len(response_times)
    output['avg_response_time'] = avg_response_time
    output['response_variance'] = response_variance
    try:
        with open('client.log', 'r') as f:
            prove_times = [float(time) for (_, time) in matches]
            pattern = r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}).*Will send proof"
            send_amortized_proof_times = re.findall(pattern, log)
            date_format = '%Y-%m-%d %H:%M:%S,%f'
            send_amortized_proof_times = [datetime.strptime(time, date_format) for time in send_amortized_proof_times]
        with open('middlebox_stderr.log', 'r') as f:
            log = f.read()
            pattern = r"Batch verify ([\d.]+) proofs takes ([\d.]+) ms"
            matches = re.findall(pattern, log)
            verify_times = [float(time) for (_, time) in matches]
            pattern = r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}).*Received amortized proof"
            receive_amortized_proof_times = re.findall(pattern, log)
            date_format = '%Y-%m-%d %H:%M:%S.%f'
            receive_amortized_proof_times = [datetime.strptime(time, date_format) for time in receive_amortized_proof_times]
        amortized_proof_communication_cost = []
        for idx in range(0, len(send_amortized_proof_times)):
            send_time = send_amortized_proof_times[idx]
            receive_time = receive_amortized_proof_times[idx]
            time_diff = (receive_time - send_time).total_seconds() * 1000
            amortized_proof_communication_cost.append(time_diff)
        amortized_proof_communication_cost = amortized_proof_communication_cost
        avg_comm_time = sum(amortized_proof_communication_cost) / len(amortized_proof_communication_cost)
        avg_prove_time = sum(prove_times) / len(prove_times)
        avg_verify_time = sum(verify_times) / len(verify_times)
        output['avg_prove_time'] = avg_prove_time
        output['avg_verify_time'] = avg_verify_time
        output['avg_comm_time'] = avg_comm_time
    except:
        print("Seems to be no_policy mode")
    print(output)
    return output

def client_analysis(exp, mode):
    output = {}
    with open('client.log', 'r') as f:
        log = f.read()
        pattern = r"Receive response takes ([\d.]+.[\d.]+)"
        matches = re.findall(pattern, log)
        response_times = [float(time) for time in matches]
        if mode not in ['no_policy', 'no_privacy']:
            pattern = r"Batch generating ([\d.]+) proofs takes ([\d.]+.[\d.]+) seconds"
            matches = re.findall(pattern, log)
            prove_times = [float(time) for (_, time) in matches]
            pattern = r"Get DotChannelOpenProver takes ([\d.]+.[\d.]+) seconds"
            get_dot_co_prover_time = float(re.findall(pattern, log)[0]) * 1000
            pattern = r"Generate CO proof takes ([\d.]+.[\d.]+) seconds"
            co_prove_time = float(re.findall(pattern, log)[0]) * 1000
            pattern = r"Wait for middlebox verify CO takes ([\d.]+.[\d.]+) seconds"
            wait_middlebox_time = float(re.findall(pattern, log)[0]) * 1000
            pattern = r"Get Async Prover takes ([\d.]+.[\d.]+) seconds"
            get_dot_amortized_prover_time = float(re.findall(pattern, log)[0]) * 1000
            pattern = r"channel opening takes ([\d.]+.[\d.]+) seconds"
            co_total_time = float(re.findall(pattern, log)[0]) * 1000
            pattern = r"Setup takes ([\d.]+.[\d.]+) s"
            setup_total_time = float(re.findall(pattern, log)[0]) * 1000
            pattern = r"Precomp 16 takes ([\d.]+.[\d.]+)"
            try:
                precomp_time = float(re.findall(pattern, log)[0])
            except Exception:
                precomp_time = 0
            pattern = r"Set up tcp takes ([\d.]+.[\d.]+) sec"
            tcp_time = float(re.findall(pattern, log)[0]) * 1000
            pattern = r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}).*Will send proof"
            send_amortized_proof_times = re.findall(pattern, log)
            date_format = '%Y-%m-%d %H:%M:%S,%f'
            send_amortized_proof_times = [datetime.strptime(time, date_format) for time in send_amortized_proof_times]
    with open('middlebox_stderr.log', 'r') as f:
        log = f.read()
        pattern = r"Batch verify ([\d.]+) proofs takes ([\d.]+) ms"
        matches = re.findall(pattern, log)
        verify_times = [float(time) for (_, time) in matches]
        pattern = r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}).*Received amortized proof"
        receive_amortized_proof_times = re.findall(pattern, log)
        date_format = '%Y-%m-%d %H:%M:%S.%f'
        receive_amortized_proof_times = [datetime.strptime(time, date_format) for time in receive_amortized_proof_times]
        pattern = r"Verify Precomp takes ([\d.]+) ms"
        matches = re.findall(pattern, log)
        precomp_verify_times = [int(time) for (time) in matches]
    # test exclude first
    response_times = response_times[1:]
    # test end
    response_variance = numpy.var(response_times)
    avg_response_time = sum(response_times) / len(response_times) * 1000
    output['avg_response_time'] = avg_response_time
    if mode not in ['no_policy', 'no_privacy']:
        amortized_proof_communication_cost = []
        for idx in range(0, len(send_amortized_proof_times)):
            send_time = send_amortized_proof_times[idx]
            receive_time = receive_amortized_proof_times[idx]
            time_diff = (receive_time - send_time).total_seconds() * 1000
            amortized_proof_communication_cost.append(time_diff)
        amortized_proof_communication_cost = amortized_proof_communication_cost[1:]
        prove_times = prove_times[1:]
        verify_times = verify_times[1:]
        avg_prove_time = sum(prove_times) / len(prove_times) * 1000
        avg_verify_time = sum(verify_times) / len(verify_times)
        avg_comm_time = sum(amortized_proof_communication_cost) / len(amortized_proof_communication_cost)
        try:
            precomp_verify_times = precomp_verify_times[1:]
            avg_precomp_verify_times = sum(precomp_verify_times) / len(precomp_verify_times)
        except:
            avg_precomp_verify_times = 0
        output['get_dot_co_prover_time'] = get_dot_co_prover_time
        output['co_prove_time'] = co_prove_time
        output['wait_middlebox_time'] = wait_middlebox_time
        output['get_dot_amortized_prover_time'] = get_dot_amortized_prover_time
        output['co_total_time'] = co_total_time
        output['avg_prove_time'] = avg_prove_time
        output['avg_verify_time'] = avg_verify_time
        output['setup_total_time'] = setup_total_time
        output['precomp_time'] = precomp_time
        output['tcp_time'] = tcp_time
        output['response_variance'] = response_variance
        output['avg_amortized_proof_communication_cost'] = avg_comm_time
        print(f"avg response time {avg_response_time}, avg prove time {avg_prove_time}, avg verify time {avg_verify_time}, avg comm time {avg_comm_time}")
        remainder = avg_response_time - avg_prove_time - avg_verify_time - avg_comm_time
        print(f"remainder {avg_response_time - avg_prove_time - avg_verify_time - avg_comm_time}")
        output['remainder'] = remainder
        output['avg_precomp_verify_times'] = avg_precomp_verify_times
    else:
        print("avg response time", avg_response_time)
    return output

def set_A_analysis(path):
    outputs = []
    for f in os.listdir(path):
        output = {}
        m = {
            'client_no_policy_undefined_undefined': 'no_policy',
            'client_sync_no_precompute_no_batch': 'not_no_policy',
            'client_sync_should_precompute_no_batch': 'not_no_policy',
            'client_async_no_precompute_no_batch': 'not_no_policy',
            'client_no_privacy_undefined_undefined': 'no_privacy'
        }
        for exp in ['client_no_privacy_undefined_undefined', 'client_no_policy_undefined_undefined', 'client_sync_no_precompute_no_batch', 'client_sync_should_precompute_no_batch', 'client_async_no_precompute_no_batch']:
            try:
                os.chdir(os.path.join(path, f, exp))
                output[exp] = client_analysis(exp, m[exp])
            except Exception as e:
                print(e)
        outputs.append(output)
    print(json.dumps(outputs))

def set_B_analysis(path, time):
    os.chdir(path)
    outputs = []
    for mode in ['async']:
        for batch_size in [1, 4, 16, 64]:
            for num_clients in [16]:
                output = {'mode': mode, 'batch_size': batch_size, 'num_clients': num_clients}
                cwd = os.getcwd()
                next_dir = f'scalability_{mode}_{num_clients}_{batch_size}_num_0_LENGTH_{time}s'
                try:
                    os.chdir(next_dir)
                    (middlebox_received, middlebox_verified_proofs, client_sent_proofs, max_mem, middlebox_throughput, actual_workload) = scalability_analyze(num_clients, batch_size, time)
                    output['middlebox_processed'] = middlebox_verified_proofs
                    output['client_sent_proofs'] = client_sent_proofs
                    output['max_mem'] = max_mem
                    output['middlebox_received'] = middlebox_received
                    output['middlebox_throughput'] = middlebox_throughput
                    output['workload'] = num_clients * 32
                    output['status'] = 'OK'
                    output['actual_workload'] = actual_workload
                except Exception as e:
                    # print(e)
                    output['status'] = 'Failed'
                os.chdir(cwd)
                outputs.append(output)
    print(json.dumps(outputs))

def client_experiment(current_time, mode, should_precompute, should_batch, protocol):
    kill_threads = []
    # TODO: kill all here
    for line in list(client_addrs.split('\n')):
        addr = line.split(' ')[0]
        t = threading.Thread(target=client_cleanup, args=(addr, 'kill.log'))
        t.start()
        kill_threads.append(t)
    for t in kill_threads:
        t.join()
    print("All clients prepared")
    print(mode, should_precompute, should_batch)
    os.chdir(os.path.join(dir_path, 'log'))
    try:
        os.mkdir(current_time)
    except:
        pass
    os.chdir(current_time)
    directory_name = f"client_{mode}_{should_precompute}_{should_batch}"
    os.mkdir(directory_name)
    os.chdir(directory_name)
    threads = []
    t = threading.Thread(target=middlebox_run, args=(middlebox_addr, mode, protocol, "false"))
    t.start()
    threads.append(t)
    if protocol == 'Regex':
        remote_tlsserver = RemoteTLSServer(tlsserver_addr)
        t = threading.Thread(target=remote_tlsserver.restart)
        t.start()
        threads.append(t)
    time.sleep(5)
    # client_addr = list(client_addrs.split('\n'))[0]
    def start_client(addr, log_file, mode, should_precompute, should_batch):
        client = Client(addr, log_file)
        client.update_git()
        if protocol == "Regex":
            regex_remote_ip = remote_ip
            # regex_remote_ip = '142.250.65.164'
        else:
            regex_remote_ip = '8.8.8.8'
        if mode != 'no_policy' and mode != 'no_privacy':
            b = f"sudo ip r add {regex_remote_ip} via 192.168.0.1; sudo /usr/bin/time -v timeout {EXPERIMENT_TIME}s ./venv/bin/python main.py custom {should_precompute} {should_batch} {protocol} ChaCha constant 1 0.001 {regex_remote_ip} true"
        else:
            b = f"sudo ip r add {regex_remote_ip} via 192.168.0.1; sudo /usr/bin/time -v timeout {EXPERIMENT_TIME}s ./venv/bin/python main.py no_middlebox {protocol} ChaCha constant 1 {regex_remote_ip} true"
        client.run_experiment_cmd(b)
    t = threading.Thread(target=start_client, args=(first_client, "client.log", mode, should_precompute, should_batch))
    t.start()
    threads.append(t)
    for t in threads:
        t.join()
    if protocol == 'Regex':
        regex_analysis()
    else:
        client_analysis(directory_name, mode)

def format():
    for filename in os.listdir('.'):
        # check if the file name starts with "thread."
        if filename.startswith("thread."):
            # print the file name
            os.system(f"column -t -s ',' {filename} > formated_{filename}")

def analyze(log_folder):
    time_regex = r"Receive response takes (.+)::"
    times = []
    for filename in os.listdir(log_folder):
        if filename.endswith(".log"):
            with open(os.path.join(log_folder, filename), "r") as f:
                for line in f:
                    match = re.search(time_regex, line)
                    if match:
                        time = float(match.group(1))
                        times.append(time)
    print(np.mean(times))

def scalability_analyze(num_clients, batch_size, time):
    print("time is", time)
    with open('middlebox_stderr.log', 'r') as f:
        text = f.read()
        pattern = f"Enter amortized_proof ([\d.]+)"
        matches = re.findall(pattern, text)
        result = [int(num) for num in matches]
        middlebox_received = sum(result)
        pattern = r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}).*Batch verify ([\d.]+) proofs takes ([\d.]+) ms"
        matches = re.findall(pattern, text)
        result = [int(num) for (_, num, _) in matches]
        matched_lines = []
        for line in text.split('\n'):
            if re.search(pattern, line):
                matched_lines.append(line)
        first_verify = matches[0][0]
        last_verify = matches[-1][0]
        date_format = '%Y-%m-%d %H:%M:%S.%f'
        first_time = datetime.strptime(first_verify, date_format)
        last_time = datetime.strptime(last_verify, date_format)
        time_diff = (last_time - first_time).total_seconds()
        total_time = sum([int(time) for (_, _, time) in matches])
        middlebox_processed = sum(result[1:])
        print("time diff is", time_diff)
        # first 10 second is waiting for setup
        middlebox_throughput = middlebox_processed / time_diff
        pattern = r"Maximum resident set size \(kbytes\): ([\d.]+)"
        max_mem = int(re.findall(pattern, text)[0]) / 1024 / 1024
        # print(sum(result))
    client_sent = 0
    for i in range(1, num_clients + 1):
        with open(f'client_{i}.log', 'r') as f:
            pattern = r"Send proof of batch size ([\d.]+)"
            matches = re.findall(pattern, f.read())
            result = [int(num) for num in matches]
            s = sum(result)
            client_sent += s
    actual_workload = client_sent / (time - 10) 
    print(f"client sent: {client_sent}; middlebox processed {middlebox_processed}")
    print(f"number of clients: {num_clients}; batch size: {batch_size} throughput: {middlebox_throughput}; workload: {actual_workload}; avg time for one proof {total_time/middlebox_processed}; max_mem {max_mem}")
    return (middlebox_received, middlebox_processed, client_sent, max_mem, middlebox_throughput, actual_workload)

def batch_run(batch_size, num_clients):
    try:
        os.mkdir(f'batch_micro_exp_{batch_size}_{num_clients}')
    except:
        pass
    os.chdir(f'batch_micro_exp_{batch_size}_{num_clients}')
    print(f"Batch size {batch_size}, Num clients {num_clients}")
    middlebox = Middlebox(middlebox_addr)
    middlebox.batch_self_benchmark_experiment(batch_size, num_clients)
    batch_analysis('.', num_clients, batch_size)

def batch_analysis(path, num_clients, batch_size):
    with open(os.path.join('middlebox_stderr.log')) as f:
        text = f.read()
        pattern = r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}).*Batch verify finish ([\d]+)"
        matches = re.findall(pattern, text)
        first_time = matches[0][0]
        last_time = matches[-1][0]
        date_format = '%Y-%m-%d %H:%M:%S.%f'
        first_time = datetime.strptime(first_time, date_format)
        last_time = datetime.strptime(last_time, date_format)
        verified_time = (last_time - first_time).total_seconds()
        verified = sum([int(m) for (_, m) in matches])
        pattern = r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}).*Batch prove send ([\d]+)"
        matches = re.findall(pattern, text)
        first_time = matches[0][0]
        last_time = matches[-1][0]
        date_format = '%Y-%m-%d %H:%M:%S.%f'
        first_time = datetime.strptime(first_time, date_format)
        last_time = datetime.strptime(last_time, date_format)
        sent_time = (last_time - first_time).total_seconds()
        send = sum([int(m) for (_, m) in matches])
        verify_rate = verified / verified_time
        workload_rate = send / sent_time
        pattern = r"Normal verifier takes ([\d]+)"
        matches = re.findall(pattern, text)
        total_verify_time = sum([int(m) for m in matches])
        avg_verify_time = total_verify_time / len(matches)
        pattern = r"Chunk verifier takes ([\d]+)"
        matches = re.findall(pattern, text)
        total_chunk_verify_time = sum([int(m) for m in matches])
        avg_chunk_verify_time = total_chunk_verify_time / len(matches)
        print(verify_rate, workload_rate, "Avg verify:", avg_verify_time, "Chunk verify:", avg_chunk_verify_time)
        return (verify_rate, workload_rate, avg_verify_time)

if __name__ == '__main__':
    now = datetime.now()
    current_time = now.strftime(f"%Y-%m-%d_%H-%M-%S")
    if sys.argv[1] == 'prepare':
        os.chdir('log')
        os.mkdir(current_time)
        os.chdir(current_time)
        print(current_time)
        threads = []
        middlebox = Middlebox(middlebox_addr)
        t = threading.Thread(target=middlebox.prepare)
        t.start()
        threads.append(t)
        tlsserver = RemoteTLSServer(tlsserver_addr)
        t = threading.Thread(target=tlsserver.prepare)
        t.start()
        threads.append(t)
        idx = 1
        for line in client_addrs.split('\n'):
            client = Client(line, f'client_{idx}.log')
            idx += 1
            t = threading.Thread(target=client.prepare)
            t.start()
        for t in threads:
            t.join()
    elif sys.argv[1] == 'analyze_A':
        set_A_analysis(sys.argv[2])
    elif sys.argv[1] == 'analyze_B':
        set_B_analysis(sys.argv[2], int(sys.argv[3]))
    elif sys.argv[1] == 'exp_B':
        # for (batch_size, num_clients) in [(1, 1), (1, 5), (1, 10), (1, 15), (1, 20), (1, 25), (1, 29), (2, 1), (2, 5), (2, 10), (2, 15), (2, 20), (2, 25), (2, 29), (4, 1), (4, 5), (4, 10), (4, 15), (4, 20), (4, 25), (4, 29), (8, 1), (8, 5), (8, 10), (8, 15), (8, 20), (8, 25), (8, 29), (16, 1), (16, 5), (16, 10), (16, 15), (16, 20), (16, 25), (16, 29), (32, 1), (32, 5), (32, 10), (32, 15), (32, 20), (32, 25), (32, 29)]:
        #         scalability_experiment_avg(current_time, num_clients, 'async', batch_size, 5)
        # for (batch_size, num_clients) in [(1, 1), (1, 5), (1, 10), (1, 15), (1, 20), (1, 25), (1, 29), (2, 1), (2, 5), (2, 10), (2, 15), (2, 20), (2, 25), (2, 29), (4, 1), (4, 5), (4, 10), (4, 15), (4, 20), (4, 25), (4, 29), (8, 1), (8, 5), (8, 10), (8, 15), (8, 20), (8, 25), (8, 29), (16, 1), (16, 5), (16, 10), (16, 15), (16, 20), (16, 25), (16, 29), (32, 1), (32, 5), (32, 10), (32, 15), (32, 20), (32, 25), (32, 29)]:
        #         scalability_experiment(current_time, num_clients, 'sync', batch_size)
        # for batch_size in [1, 2, 4, 8, 16]:
        #     scalability_experiment(current_time, 29, 'async', batch_size)
        for _ in range(5):
            now = datetime.now()
            current_time = now.strftime(f"%Y-%m-%d_%H-%M-%S")  
            for num_clients in [1]:
                for batch_size in [1, 4, 16, 64]:
                    try:
                        scalability_experiment_avg(current_time, num_clients, 'async', batch_size, 1, remote_ip, 'Dot')
                    except:
                        print("something wrong")
    elif sys.argv[1] == 'exp_A':
        for _ in range(5):
            now = datetime.now()
            current_time = now.strftime(f"%Y-%m-%d_%H-%M-%S")
            client_experiment(current_time, 'sync', 'should_precompute', 'no_batch', 'Dot')
            client_experiment(current_time, 'sync', 'no_precompute', "no_batch", 'Dot')
            client_experiment(current_time, 'async', 'no_precompute', 'no_batch', 'Dot')
            client_experiment(current_time, 'no_policy', 'undefined', 'undefined', 'Dot')
            # client_experiment(current_time, 'no_privacy', 'undefined', 'undefined', 'Dot')
    elif sys.argv[1] == 'Regex':
        for _ in range(5):
            now = datetime.now()
            current_time = now.strftime(f"%Y-%m-%d_%H-%M-%S")
            # client_experiment(current_time, 'sync', 'should_precompute', "no_batch", 'Regex')
            # client_experiment(current_time, 'sync', 'no_precompute', "no_batch", 'Regex')
            # client_experiment(current_time, 'async', 'no_precompute', "no_batch", 'Regex')
            client_experiment(current_time, 'no_policy', 'undefined', 'undefined', 'Regex')
    elif sys.argv[1] == 'Regex_analysis':
        path = sys.argv[2] 
        os.chdir(sys.argv[2])
        print(os.getcwd())
        outputs = []
        for f in os.listdir(path):
            output = []
            for exp in ['client_no_policy_undefined_undefined', 'client_sync_no_precompute_no_batch', 'client_sync_should_precompute_no_batch', 'client_async_no_precompute_no_batch']:
                new_path = os.path.join(path, f, exp)
                # print(new_path)
                os.chdir(new_path)
                res = regex_analysis()
                output.append(res)
            outputs.append(output)
        print(json.dumps(outputs))
    elif sys.argv[1] == 'test_congestion':
        os.chdir(os.path.join(dir_path, 'log'))
        try:
            os.mkdir(current_time)
        except Exception as e:
            print(e)
        os.chdir(current_time)
        BATCH_SIZE = 22
        directory_name = f"test_congestion_{BATCH_SIZE}"
        os.mkdir(directory_name)
        os.chdir(directory_name)
        threads = []
        def start_middlebox(addr):
            middlebox = Middlebox(addr)
            middlebox.congestion_control_experiment(BATCH_SIZE)
        t = threading.Thread(target=start_middlebox, args=(middlebox_addr,))
        t.start()
        threads.append(t)
        time.sleep(5)
        # client_addr = list(client_addrs.split('\n'))[0]
        def start_client(addr, log_file):
            client = Client(addr, log_file)
            client.kill()
            client.no_policy_experiment(BATCH_SIZE)
        t = threading.Thread(target=start_client, args=(first_client, "client.log"))
        t.start()
        threads.append(t)
        for t in threads:
            t.join()
    elif sys.argv[1] == 'batch_benchmark':
        try:
            os.mkdir(f'./log/{current_time}')
        except Exception as e:
            print(e)
        os.chdir(f'./log/{current_time}')
        for num_clients in [16]:
            for batch_size in [4, 1]:
                cwd = os.getcwd()
                batch_run(batch_size, num_clients)
                os.chdir(cwd)
    elif sys.argv[1] == 'batch_analysis':
        result = []
        os.chdir(sys.argv[2])
        for num_clients in [16]:
            for batch_size in [1, 64]:
                cwd = os.getcwd()
                os.chdir(f'./batch_micro_exp_{batch_size}_{num_clients}')
                (verify_rate, workload_rate, avg_verify_time) = batch_analysis(sys.argv[2], num_clients, batch_size)
                print(verify_rate, workload_rate)
                result.append({'batch_size': batch_size, 'workload': num_clients * 2.5, 'through_workload': f"{verify_rate:.2f}/{workload_rate:.2f}"})
                os.chdir(cwd)
        print(json.dumps(result))