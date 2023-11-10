import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

info = bytes.fromhex('0005')
key_material = bytes.fromhex('0005')
hkdf = HKDFExpand(
    algorithm=hashes.SHA256(),
    length=32,
    info=info,
)
key = hkdf.derive(key_material)
key_hex = key.hex()
for i in range(len(key_hex) // 2):
    num = key_hex[i * 2: i * 2 + 2]
    print(int(num, 16), end=', ')
print("")