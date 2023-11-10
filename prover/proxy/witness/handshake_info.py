from . import sha2_compressions
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)
from ..merkle.poseidon_hash import PoseidonHashGenerator
from chacha20poly1305 import ChaCha20Poly1305

class HandshakeInfoGenerator:
    def __init__(self, curve, cipher):
        self.curve = curve
        self.cipher = cipher

    # takes bytearray key, iv as input; string plaintext
    def encrypt_aes_gcm(self, key, iv, plaintext):
        encryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
        ).encryptor()

        ciphertext = encryptor.update(bytes.fromhex(plaintext)) + encryptor.finalize()

        return ciphertext

    # takes bytearray key, iv as input; string plaintext
    def encrypt_aes_gcm(self, key, iv, plaintext):
        if self.cipher == "aes128gcm":
            encryptor = Cipher(
                algorithms.AES(key),
                modes.GCM(iv),
            ).encryptor()
            ciphertext = encryptor.update(bytes.fromhex(plaintext)) + encryptor.finalize()
            return ciphertext
        elif self.cipher == "chacha20-poly1305":
            cip = ChaCha20Poly1305(key)
            ciphertext = cip.encrypt(iv, bytes.fromhex(plaintext))[0:-16]
            return ciphertext
        else:
            raise NotImplementedError

    def get_handshake_dict(self, tlsconn):
        # We have configured tlsconn to store the following values
        psk             = tlsconn.psk
        ec_sk           = tlsconn.clientPrivate
        ec_pk_client    = tlsconn.clientPublic
        ec_pk_server    = tlsconn.serverPublic
        hs              = tlsconn.handshakeSecret
        ch_sh           = tlsconn.serverHelloTranscript
        H_2             = tlsconn.serverHelloTranscriptHash
        H_7             = tlsconn.serverExtensionsTranscriptHash
        SF              = tlsconn.serverFinishedValue
        H_3             = tlsconn.serverFinishedTranscriptHash

        len_sh = len(tlsconn.serverHelloTranscript)

        # server's handshake key
        tk_shs = tlsconn.serverHSKey
        iv_shs = tlsconn.serverHSIV

        # client application key
        # used for verification
        c_ap_key = tlsconn._recordLayer._writeState.encContext.key
        c_ap_iv = tlsconn._recordLayer._writeState.fixedNonce

        # tlsconn stores the plaintext of the transcripts sent
        # A bit of a hack, but  we just encrypt them to get the ciphertexts that are input to the circuit
        tr_7 = tlsconn.serverExtensionsTranscript # CH || SH || Extensions_without_SF_value
        ct_7 = self.encrypt_aes_gcm(tk_shs, iv_shs, tr_7[len_sh:]).hex()

        # obtain ct_3, the encrypted part of tr3
        tr3 = tlsconn.serverFinishedTranscript # CH || SH || Extensions_with_SF_value
        ct_3 = self.encrypt_aes_gcm(tlsconn.serverHSKey, tlsconn.serverHSIV, tr3[len_sh:]).hex()

        # This function returns the checkpoint SHA256 state (H values) for tr7 
        # By checkpoint, this means this is the H-value at the last whole SHA block of tr7 (without padding)
        H_state_tr7 = sha2_compressions.get_H_state(tlsconn.serverExtensionsTranscript)

        if self.cipher == 'aes128gcm':
            key_iv_poseidon_hash = hex(PoseidonHashGenerator(self.curve).poseidon_hash([0, int(c_ap_key.hex() + c_ap_iv.hex(), 16)]))[2:]
        elif self.cipher == "chacha20-poly1305":
            concat = '0' * 40 + c_ap_key.hex() + c_ap_iv.hex()
            key_iv_poseidon_hash = hex(PoseidonHashGenerator(self.curve).poseidon_hash([int(concat[:64], 16), int(concat[64:], 16)]))[2:]
        else:
            raise NotImplementedError

        # ciphertext is not required in ChannelShortcut_only_CO, so they are replaced with placeholder here
        hs_dict = {
            "psk": psk,
            "ec_sk": ec_sk[2:],
            "ec_pk_client_x": ec_pk_client[2:66],
            "ec_pk_client_y": ec_pk_client[66:],
            "ec_pk_server_x": ec_pk_server[2:66],
            "ec_pk_server_y": ec_pk_server[66:],
            "HS": hs,
            "H_2": H_2,
            "ct_7": ct_7,
            "H_7": H_7,
            "SF": SF,
            "ch_sh": ch_sh,
            "ct_3": ct_3,
            "H_3": H_3, 
            "dns_ciphertext": "dns_ciphertext",
            "s_hs_key": tlsconn.serverHSKey.hex(),
            "s_hs_iv": tlsconn.serverHSIV.hex(),
            "c_ap_key": c_ap_key.hex(),
            "c_ap_iv": c_ap_iv.hex(),
            "dns_plaintext": "dns_plaintext",
            "H_state_tr7": H_state_tr7,
            "key_iv_poseidon_hash": key_iv_poseidon_hash
        }

        return hs_dict
        

    def transform_handshake_dict(self, hs_dict):
        test_doh = ""
        test_doh += hs_dict['psk'] + "\n"
        test_doh += hs_dict['ec_sk'] + "\n"
        test_doh += hs_dict['ec_pk_client_x'] + "\n"
        test_doh += hs_dict['ec_pk_client_y'] + "\n"
        test_doh += hs_dict['ec_pk_server_x'] + "\n"
        test_doh += hs_dict['ec_pk_server_y'] + "\n"
        test_doh += hs_dict['HS'] + "\n"
        test_doh += hs_dict['H_2'] + "\n"
        test_doh += hs_dict['H_7'] + "\n"
        test_doh += hs_dict['H_3'] + "\n"
        test_doh += hs_dict['SF'] + "\n"
        test_doh += hs_dict['ch_sh'] + "\n"
        test_doh += hs_dict['ct_3'] + "\n"
        test_doh += hs_dict['dns_ciphertext'] + "\n"
        test_doh += hs_dict['H_state_tr7'] + "\n"
        test_doh += hs_dict['key_iv_poseidon_hash'] + "\n"
        test_doh += "******** EXPECTED VALUES BELOW ********" + "\n"
        test_doh += "plaintext: " + hs_dict['dns_plaintext'] + "\n"
        test_doh += "H3: " + hs_dict['H_3'] + "\n"
        test_doh += "s hs key: " + hs_dict['s_hs_key'] + "\n"
        test_doh += "s hs iv: " + hs_dict['s_hs_iv'] + "\n"
        test_doh += "c ap key: " + hs_dict['c_ap_key'] + "\n"
        test_doh += "c ap iv: " + hs_dict['c_ap_iv'] + "\n"
        return test_doh

    def get_handshake_info(self, tlsconn):
        hs_dict = self.get_handshake_dict(tlsconn)
        return hs_dict