from tlslite.utils.chacha import ChaCha
from dnslib import DNSRecord


key = bytearray.fromhex("ef1199024525d18db60d5d620e893037616c7d15bc0146d309dba3b0d1f11b79")
iv = bytearray.fromhex("7dc3b36ced2426918f6cdea7")
cipher = ChaCha(key, iv, counter=1)
ciphertext = bytearray.fromhex('2a5a7e9a64ad2c11e8597c2c428b5f00ef8597b6025bc2a7949c7bd9b958d78b1bf76baff96aa43e75c1c1a94e7e74')
data = cipher.decrypt(ciphertext)
print(data)

# key = bytearray.fromhex("daa6d063c6d76836b02769364a7d924502d6d902451a025ae39e82b0ff1e8f91")
# iv = bytearray.fromhex("6b81bc8abc00c6bdb71ff9a4")
# cipher = ChaCha(key, iv, counter=1)
# ciphertext = bytearray.fromhex('80884da44d5996c9f255174fcafb4be725a3d63a9e7f05d36f43dcc1dbac24afd3d262461f33dbd95e1c456a3e144bce798f1db742')
# data = cipher.decrypt(ciphertext)
# print(data[15:-4])
