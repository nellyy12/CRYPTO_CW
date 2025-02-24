import os
from Crypto.Cipher import AES
from Crypto.Util import Counter

class AES_GCM:
    def __init__(self, key):
        assert len(key) == 32, "AES-GCM key must be 32 bytes."
        self.key = key

    def encrypt(self, plaintext):
        iv = os.urandom(12)
        counter = Counter.new(128, initial_value=int.from_bytes(iv, byteorder="big"))
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=iv)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
        return iv + tag + ciphertext  # Combine IV, tag, and ciphertext

    def decrypt(self, encrypted_data):
        iv = encrypted_data[:12]
        tag = encrypted_data[12:28]
        ciphertext = encrypted_data[28:]
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=iv)
        return cipher.decrypt_and_verify(ciphertext, tag).decode()
