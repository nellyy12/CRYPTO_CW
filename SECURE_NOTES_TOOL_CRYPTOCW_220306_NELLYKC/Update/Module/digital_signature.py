import os
from ecdsa import SigningKey, VerifyingKey, NIST256p

class ECDSA:
    @staticmethod
    def generate_key_pair():
        private_key = SigningKey.generate(curve=NIST256p)
        public_key = private_key.verifying_key
        return private_key, public_key.to_pem()

    @staticmethod
    def save_private_key(private_key, filename):
        """Save a private key to a PEM file."""
        with open(filename, "wb") as f:
            f.write(private_key.to_pem())

    @staticmethod
    def load_private_key(filename):
        """Load a private key from a PEM file."""
        try:
            with open(filename, "rb") as f:
                return SigningKey.from_pem(f.read())
        except FileNotFoundError:
            return None  # Handle missing key gracefully

    @staticmethod
    def sign(private_key, data):
        return private_key.sign(data.encode())

    @staticmethod
    def verify(public_key_pem, signature, data):
        public_key = VerifyingKey.from_pem(public_key_pem)
        try:
            return public_key.verify(signature, data.encode())
        except:
            return False
