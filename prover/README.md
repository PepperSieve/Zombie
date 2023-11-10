# ZKMB prototype instruction
## Step 1: setup network
We need at least two devices to test the prototype, one for prover and one for middlebox(verifier)

Before connecting the prover and middlebox, make sure the middlebox can connect to the public network

We need an internal network for the prover and middlebox to communicate with each other, we can directly connect the prover and middlebox with an ethernet cable. (If there are multiple provers, we need a switch to build connect multiple devices together). 

If we run `ifconfig` on the prover and middlebox, we can see there is a new network interface for the internal network

To setup the internal network, on the prover, run
```
INT=<prover internal interface>
sudo ip addr add 10.0.0.2/24 dev $INT
```
on the middlebox, run
```
INT=<middlebox internal interface>
sudo ip addr add 10.0.0.1/24 dev $INT
```
These commands setup a temporary ip for the device, which will be lost after a reboot

These two ip addresses are hardcoded in the code, changing it will cause problems

To setup the middlebox as a router, enter the middlebox directory, run
```
./iptable-configure.sh
``` 

## Step 2: setup environment
on the middlebox, make sure the current directory is middlebox, run 

```
./configure.sh
```

on the prover, make sure the current directory is the prover, run
```
./configure.sh
```

At the last line of `configure.sh`, we setup a default gateway for traffic to `1.1.1.1`, which is the cloudflare dns server

the `pk` and `pvk` will be generated in `data` folder, distribute the `doh_pvk` and `co_pvk` manually to the data folder of middlebox

Since it is hard to bridge java to python, the circuit assignment generator is implemented as java server, before running the dnsserver, cd into the gen folder, run
```
java -Xmx10g -cp bin:json-20220320.jar server.CoServer
```
this will block the process, in another terminal, run
```
java -Xmx10g -cp bin:json-20220320.jar server.DohServer
```

## Step 3: run dnsserver and test

to run the middlebox, enter the middlebox folder on the middleox, run 
```
sudo python3 middlebox.py
```

to run the dnsserver, since we need to use the 53 port, we have to run as sudo
```
# make sure your current directory is exactly the prover folder
sudo ./venv/bin/python dnsserver.py
```

After that, the dnsserver will be started, we can test it in another terminal by running

```
nslookup -timeout=600 google.com localhost
```

or configure the client dns server address to be `127.0.0.1`, then all dns request will be forwarded to the dnsserver

# Architecture
The prototype of ZKMB is implemented as a dns proxy on the client, it accepts dns request from localhost, convert it to doh request, send the request, generate a proof, and send the proof to the verifier, then read the doh response, and forward it back to localhost.

To generate the circuit assignment based on the tcp traffic, we run two java servers to accept description of circuit inputs as json, and send back to the verifier the circuit assignments

We have to run two java servers since the class initialization, circuit generation, and assignment generation has a lot of side effects. If we initialize two circuit generators, at least one of them can't work properly. It is hard to debug the code, so running two java servers is the most convenient choice at this time.

# Baseline Bencnmark

// These number vary a lot each trial

For 50 queries
- no policy
  - DoT (handshake each time): 3.64s 
  - DoT (long connection): 1.89s
  - DNS: 1.90s
- no privacy
  - DNS (route through middlebox, being checked for policy compliance) : 2.08s

# CirC Benchmark

Environment:

- Prover
  - CPU: AMD Ryzen 5 3600 6-Core Processor
  - Cores: 6 Core, 12 Thread
  - Memory: 16GB

Verifier
  - Intel(R) Celeron(R) N4020 CPU @ 1.10GHz
  - Cores: 2 Core, 2 Thread
  - Memory: 4GB

## Dot ChaCha Spartan

### Send a DNS request

| Name                       | Time (seconds)  |
| ----                       | ----  |
| **prover**                 |       |
| transcript generation time | 0.138 |
| proof generation time      | 0.716 |
| wait for verify time       | 0.281 |
| - total                    | 1.135 |
| **verifier**               |       |
|verifier total time         | 0.258 |

| Name                       | Time (seconds)  |
| ----                       | ----  |
| **proof generation time** breakdown|   |
| circuit evaluation time  | 0.212 |
| transform to spartan r1cs| 0.105 |
| spartan prove            | 0.399 |
| - total                  | 0.716 |

### Dot ChaCha ChannelOpen

| Name                       | Time (seconds)  |
| ----                       | ----  |
| transcript generation time | 0.015 |
| **proof generation time** breakdown|   |
| circuit evaluation time  | 0.639 |
| transform to spartan r1cs| 0.664 |
| spartan prove            | 2.437 |
| - total                  | 3.740 |
| **verifier**             |       |
|verifier total time       | 1.612 |

# xjsnark Benchmark

Environment:

CPU: Intel(R) Xeon(R) Platinum 8375C CPU @ 2.90GHz 

CORES: 32

MEMORY: 128GB

Notes:

transcript generation time is the time taken to extract infomation from the traffic and prepare it into the public inputs and witness of circuits, such as the merkel proof generation

assignment generation time = circuit evaluation time + write to buffer time + network cost

prover intrinsic time = transcript generation time + circuit evaluation time + proof generation time

prover total time = prover intrinsic time + prover overhead

## Dot ChaCha Spartan

### Channel Opening

| Name                       | Time (seconds)  |
| ----                       | ----  |
| **prover**                   |       |
| transcript generation time | 0.015 |
| assignment generation time | 0.776 |
| - circuit evaluation time  | 0.320 |
| - write to buffer time     | 0.405 |
| - network cost             | 0.051 |
| assignment preprocess time | 3.800 |
| proof generation time      | 1.948 |
| prover total time          | 6.540 |
| **prover overhead**          |       |
| prover intrinsic time      | 2.283 |
| prover overhead            | 4.256 |
| **verifier**                 |       |
|verifier total time         | 0.17630 |

### Amortized Dot Request

| Name                       | Time (seconds)  |
| ----                       | ----  |
| **prover**                   |       |
| transcript generation time | 0.173 |
| assignment generation time | 0.320 |
| - circuit evaluation time  | 0.082 |
| - write to buffer time     | 0.210 |
| - network cost             | 0.028 |
| assignment preprocess time | 0.583 |
| proof generation time      | 0.327 |
| prover total time          | 1.404 |
| **prover overhead**          |       |
| prover intrinsic time      | 0.582 |
| prover overhead            | 0.821 |
| **verifier**                 |       |
|verifier total time         | 0.04708 |

## Dot ChaCha Groth16

### Channel Opening

| Name                       | Time (seconds)  |
| ----                       | ----  |
| **prover**                   |       |
| transcript generation time | 0.015 |
| assignment generation time | 0.709 |
| - circuit evaluation time  | 0.250 |
| - write to buffer time     | 0.409 |
| - network cost             | 0.050 |
| assignment preprocess time | 3.495 |
| proof generation time      | 8.155 |
| prover total time          | 12.374 |
| **prover overhead**          |       |
| prover intrinsic time      | 8.421 |
| prover overhead            | 3.954 |
| **verifier**                 |       |
|verifier total time         | 0.00141 |

### Amortized Dot Request

| Name                       | Time (seconds)  |
| ----                       | ----  |
| **prover**                   |       |
| transcript generation time | 0.175 |
| assignment generation time | 0.471 |
| - circuit evaluation time  | 0.106 |
| - write to buffer time     | 0.329 |
| - network cost             | 0.036 |
| assignment preprocess time | 0.532 |
| proof generation time      | 1.180 |
| prover total time          | 2.358 |
| **prover overhead**          |       |
| prover intrinsic time      | 1.461 |
| prover overhead            | 0.897 |
| **verifier**                 |       |
|verifier total time         | 0.00174 |

## Doh AES Spartan

### Channel Opening

| Name                       | Time (seconds)  |
| ----                       | ----  |
| **prover**                   |       |
| transcript generation time | 0.140 |
| assignment generation time | 1.988 |
| - circuit evaluation time  | 0.412 |
| - write to buffer time     | 1.344 |
| - network cost             | 0.232 |
| assignment preprocess time | 4.241 |
| proof generation time      | 1.965 |
| prover total time          | 8.335 |
| **prover overhead**          |       |
| prover intrinsic time      | 2.517 |
| prover overhead            | 5.817 |
| **verifier**                 |       |
|verifier total time         | 0.17234 |

### Amortized Doh Request

| Name                       | Time (seconds) |
| ----                       | ----  |
| **prover**                   |       |
| transcript generation time | 0.174 |
| assignment generation time | 4.538 |
| - circuit evaluation time  | 0.492 |
| - write to buffer time     | 3.355 |
| - network cost             | 0.691 |
| assignment preprocess time | 2.707 |
| proof generation time      | 0.789 |
| prover total time          | 8.209 |
| **prover overhead**          |       |
| prover intrinsic time      | 1.455 |
| prover overhead            | 6.754 |
| **verifier**                 |       |
|verifier total time         | 0.07793 |

## Doh AES Groth16

### Channel Opening

| Name                       | Time (seconds) |
| ----                       | ----  |
| **prover**                   |       |
| transcript generation time | 0.136 |
| assignment generation time | 1.966 |
| - circuit evaluation time  | 0.424 |
| - write to buffer time     | 1.337 |
| - network cost             | 0.205 |
| assignment preprocess time | 3.883 |
| proof generation time      | 8.113 |
| prover total time          | 14.099 |
| **prover overhead**          |       |
| prover intrinsic time      | 8.674 |
| prover overhead            | 5.425 |
| **verifier**                 |       |
|verifier total time         | 0.00288 |

### Amortized Doh Request

| Name                       | Time (seconds) |
| ----                       | ----  |
| **prover**                   |       |
| transcript generation time | 0.174 |
| assignment generation time | 4.777 |
| - circuit evaluation time  | 0.722 |
| - write to buffer time     | 3.459 |
| - network cost             | 0.596 |
| assignment preprocess time | 2.638 |
| proof generation time      | 2.323 |
| prover total time          | 9.912 |
| **prover overhead**          |       |
| prover intrinsic time      | 3.219 |
| prover overhead            | 6.693 |
| **verifier**                 |       |
|verifier total time         | 0.00412 |
