import os, sys
from proxy.dot_chacha import DotChaChaProxy
from time import time

def benchmark():
    start = time()
    if sys.argv[1] == 'no_privacy':
        for _ in range(int(sys.argv[2])):
            os.system("nslookup amazon.com 1.1.1.1")
    elif sys.argv[1] == 'no_policy':
        DotChaChaProxy("Spartan", False, False, False, int(sys.argv[2]))
    elif sys.argv[1] == 'no_policy_privacy':
        for _ in range(int(sys.argv[2])):
            os.system("nslookup amazon.com 1.1.1.1")
    end = time()
    print(end - start)