from proxy.dot_chacha import DotChaChaProxy
import sys

def run_proxy():
    if sys.argv[1] == 'with_middlebox':
        DotChaChaProxy("Spartan", True, True, False, 3)
    elif sys.argv[1] == 'skip_middlebox':
        DotChaChaProxy("Spartan", True, False, False, 3)
    elif sys.argv[1] == 'no_proof':
        DotChaChaProxy("Spartan", False, False, False, 3)

if __name__ == '__main__':
    run_proxy()