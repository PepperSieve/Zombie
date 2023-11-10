from socket import socket, AF_INET, SOCK_STREAM
from tlslite import TLSConnection, HandshakeSettings
import requests, os
from handshake_info import HandshakeInfoGenerator
from tlslite.utils.cryptomath import HKDF_expand_label

co_api  = "http://localhost:8003/generate_assignment"

hs_generator = HandshakeInfoGenerator('dalek', 'chacha20-poly1305')
server_socket = socket(AF_INET, SOCK_STREAM)
server_socket.connect(('1.1.1.1', 853))
server_connection = TLSConnection(server_socket)
settings = HandshakeSettings()
settings.versions = [(3, 4)]
cipherName = "chacha20-poly1305"
settings.cipherNames = [cipherName]
settings.eccCurves = ["secp256r1"]
settings.keyShares = ["secp256r1"]
server_connection.handshakeClientCert(
    settings=settings, print_handshake=False)
c_ap_key = server_connection._recordLayer._writeState.encContext.key.hex()
c_ap_iv = server_connection._recordLayer._writeState.fixedNonce.hex()
handshake_info = hs_generator.get_handshake_info(server_connection)
json_inputs = {
    "handshake_info": handshake_info
}
response = requests.post(co_api, json=json_inputs)
print(handshake_info)

secret = HKDF_expand_label(bytes.fromhex("0a8c07a4ab7cc411b13a3f7d423d4b948169476856112edeb16782332d47a213"), bytes("s hs traffic", 'utf-8'), bytes.fromhex("a2ecdb67363e4a613707b26e28e1447f673b48b1a5a942ac8c06ba0508c34b33"), 32, 'sha256')
tk_shs = HKDF_expand_label(secret, b'key', b'', 32, 'sha256')
for b in secret:
    print(b, end=' ')

print("tkshs")
for b in tk_shs:
    print(b, end=' ')

# 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 
# 144 220 137 105 121 170 75 57 204 203 125 160 163 114 170 160 153 244 92 18 105 218 40 128 143 142 177 224 217 149 206 80 
# 234 32 8 20 34 55 251 108 135 33 7 144 
# 79 185 3 31 51 77 139 30 44 10 225 221 13 32 175 180 92 40 72 231 33 31 41 152 251 117 42 203 108 144 0 154 
# 93 135 66 57 212 193 142 95 32 3 12 173 
# 100 239 95 103 223 82 178 59 184 120 218 127 82 133 210 164 159 180 40 118 26 215 74 159 65 181 55 122 58 50 77 216 
# 50 68 220 21 17 13 149 238 142 210 193 102 65 16 53 153 220 54 70 123 67 152 242 17 172 0 49 240 164 145 27 208 
# 204 92 207 70 118 47 142 207 112 217 136 86 244 231 3 9 95 127 241 61 9 197 120 84 152 128 28 2 33 0 229 96 244 189 61 141 224 222 176 166 48 121 244 152 68 61 208 93 12 194 127 17 35 198 167 169 130 207 199 133 239 167 20 0 0 32 50 68 220 21 17 13 149 238 142 210 193 102 65 16 53 153 220 54 70 123 67 152 242 17 172 0 49 240 164 145 27 208 39 136 12 12 148 215 28 82 15 124 14 51 221 204 192 70 112 176 50 179 167 6 223 151 58 122 144 0 221 11