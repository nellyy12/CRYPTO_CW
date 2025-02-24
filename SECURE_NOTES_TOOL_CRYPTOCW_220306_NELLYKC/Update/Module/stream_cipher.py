import os
import struct

class ChaCha20:
    def __init__(self, key, nonce):
        assert len(key) == 32, "Key must be 32 bytes."
        assert len(nonce) == 12, "Nonce must be 12 bytes."
        self.key = key
        self.nonce = nonce

    def quarter_round(self, state, a, b, c, d):
        state[a] += state[b]; state[d] ^= state[a]; state[d] = (state[d] << 16) | (state[d] >> 16)
        state[c] += state[d]; state[b] ^= state[c]; state[b] = (state[b] << 12) | (state[b] >> 20)
        state[a] += state[b]; state[d] ^= state[a]; state[d] = (state[d] << 8) | (state[d] >> 24)
        state[c] += state[d]; state[b] ^= state[c]; state[b] = (state[b] << 7) | (state[b] >> 25)

    def chacha20_block(self, counter):
        constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
        key_words = struct.unpack("<8I", self.key)
        nonce_words = struct.unpack("<3I", self.nonce)
        state = list(constants) + list(key_words) + [counter] + list(nonce_words)


        for _ in range(10):  # 20 rounds (10 iterations of double rounds)
            self.quarter_round(state, 0, 4,  8, 12)
            self.quarter_round(state, 1, 5,  9, 13)
            self.quarter_round(state, 2, 6, 10, 14)
            self.quarter_round(state, 3, 7, 11, 15)
            self.quarter_round(state, 0, 5, 10, 15)
            self.quarter_round(state, 1, 6, 11, 12)
            self.quarter_round(state, 2, 7,  8, 13)
            self.quarter_round(state, 3, 4,  9, 14)

        output = b''.join(struct.pack("<I", (state[i] + constants[i % 4]) & 0xFFFFFFFF) for i in range(16))
        return output

    def encrypt(self, plaintext):
        
        plaintext.encode() if isinstance(plaintext, str) else plaintext

        keystream = b''.join(self.chacha20_block(i) for i in range((len(plaintext) // 64) + 1))
        return bytes(p ^ k for p, k in zip(plaintext, keystream[:len(plaintext)]))

    def decrypt(self, ciphertext):
        ciphertext = ciphertext.encode() if isinstance(ciphertext, str) else ciphertext  # Ensure ciphertext is bytes
        return self.encrypt(ciphertext)  # ChaCha20 decryption is symmetric
