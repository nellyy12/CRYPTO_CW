import hashlib
import os

class SHA256:
    @staticmethod
    def generate_salt(size: int = 16) -> bytes:
        """Generate a random salt of the given size (default: 16 bytes)."""
        return os.urandom(size)

    @staticmethod
    def hash(data: str, salt: bytes = None, iterations: int = 100000, return_bytes: bool = False) -> str:
        """Hashes data using SHA-256 with optional salting and iterations (key-stretching)."""
        data = data.encode() if isinstance(data, str) else data
        salt = salt or b''  # Default: no salt if not provided

        digest = hashlib.sha256(salt + data)
        for _ in range(iterations - 1):  # Key stretching
            digest = hashlib.sha256(digest.digest())

        return digest.digest() if return_bytes else digest.hexdigest()

    @staticmethod
    def hash_password(password: str) -> str:
        """Generate a salted and stretched SHA-256 hash for secure password storage."""
        salt = SHA256.generate_salt()
        hashed_password = SHA256.hash(password, salt=salt)
        return salt.hex() + ":" + hashed_password  # Store salt + hash

    @staticmethod
    def verify_password(password: str, stored_hash: str) -> bool:
        """Verify a password against a stored salted hash."""
        try:
            stored_salt, stored_hashed = stored_hash.split(":")
            hashed_input = SHA256.hash(password, salt=bytes.fromhex(stored_salt))
            return hashed_input == stored_hashed
        except ValueError:
            return False  # Invalid hash format
