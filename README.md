# Implementation of Zombie

This is the source code for Zombie, as described in [https://eprint.iacr.org/2023/1022.pdf](https://eprint.iacr.org/2023/1022.pdf).

## Repository Organization

- circ: fork of the [CirC](https://github.com/circify/circ) circuit compiler.
- middlebox: Zombie's middlebox
- prover: Zombie's client
- regex: regexp to [Zokrates](https://zokrates.github.io/) compiler
- tlsserver: simple TLS server to handle DNS traffic for experiments

## Setup
All configuration will be performed automatically by Cloudlab
1. Signup an account under project "zombie", Log in to CloudLab
2. Click this link https://www.cloudlab.us/p/zombie/ZombieProfile/0 to load the profile, and then click Next
3. Enter the "Number of clients" you want to experiment with -> Next
4. Under Cluster, choose "Cloudlab Utah" -> Next
5. Enter Experiment Duration -> Finish
6. Wait for the experiment to be configured
7. Copy the addresses of machines to `multi_client_benchmark.py`

## Experiments
To reproduce the computational overhead experiments in Section 6.1, run
```
python3 multi_client_benchmark.py exp_A
```

To reproduce the middlebox throughput experiments in Section 6.2, run
```
python3 multi_client_benchmark exp_B
```
