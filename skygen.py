import os
import hashlib
import logging
import secrets
from argon2 import PasswordHasher, exceptions
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.argon2 import Argon2
from cryptography.hazmat.backends import default_backend
from hmac import compare_digest

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Constants
SALT_SIZE = 16  # 128-bit salt
HASH_LENGTH = 32  # 256-bit hash
TIME_COST = int(os.getenv('ARGON2_TIME_COST', 2))  # Number of iterations
MEMORY_COST = int(os.getenv('ARGON2_MEMORY_COST', 2**15))  # 32 MB of memory
PARALLELISM = int(os.getenv('ARGON2_PARALLELISM', 2))  # Number of parallel threads
AES_KEY_SIZE = 32  # 256-bit AES key
AES_IV_SIZE = 12  # 96-bit IV for GCM mode

# Initialize Argon2 hasher
ph = PasswordHasher(time_cost=TIME_COST, memory_cost=MEMORY_COST, parallelism=PARALLELISM, hash_len=HASH_LENGTH)


def generate_shannon_salt() -> bytes:
    """Generate a cryptographically secure random salt."""
    return secrets.token_bytes(SALT_SIZE)


def enforce_turing_password_policy(password: str) -> bool:
    """Enforce strong password policy."""
    if len(password) < 8:
        return False
    if not any(char.isdigit() for char in password):
        return False
    if not any(char.isupper() for char in password):
        return False
    if not any(char.islower() for char in password):
        return False
    if not any(char in "!@#$%^&*()-_=+[]{}|;:'\",.<>?/`~" for char in password):
        return False
    return True


def hash_turing_password(password: str, salt: bytes) -> tuple[str, str]:
    """
    Hash a password with Argon2 and SHA-3.

    Args:
        password (str): The password to hash.
        salt (bytes): A cryptographically secure random salt.

    Returns:
        tuple: A tuple containing the SHA-3 hash and the salt in hexadecimal format.
    """
    if not enforce_turing_password_policy(password):
        raise ValueError("Password does not meet the strength requirements")

    try:
        # Hash the password with Argon2
        argon2_hash = ph.hash(password + salt.hex())

        # Combine Argon2 hash and salt, then hash with SHA-3
        combined = argon2_hash.encode() + salt
        sha3_hash = hashlib.sha3_256(combined).hexdigest()

        return sha3_hash, salt.hex()
    except Exception as e:
        logger.error("Error hashing password: %s", e)
        raise


def verify_diffie_password(stored_hash: str, stored_salt: str, password: str) -> bool:
    """
    Verify a password against the stored hash and salt.

    Args:
        stored_hash (str): The stored SHA-3 hash.
        stored_salt (str): The stored salt in hexadecimal format.
        password (str): The password to verify.

    Returns:
        bool: True if the password is valid, False otherwise.
    """
    try:
        # Recreate the combined hash
        combined = stored_hash.encode() + bytes.fromhex(stored_salt)
        sha3_hash = hashlib.sha3_256(combined).hexdigest()

        # Verify the password with Argon2
        ph.verify(stored_hash, password + stored_salt)
        return compare_digest(sha3_hash, stored_hash)
    except exceptions.VerifyMismatchError:
        logger.warning("Password verification failed: mismatch")
        return False
    except Exception as e:
        logger.error("Error verifying password: %s", e)
        raise


def derive_rivest_key(password: str, salt: bytes) -> bytes:
    """
    Derive an AES key from a password and salt using Argon2.

    Args:
        password (str): The password to derive the key from.
        salt (bytes): A cryptographically secure random salt.

    Returns:
        bytes: The derived AES key.
    """
    kdf = Argon2(
        time_cost=TIME_COST,
        memory_cost=MEMORY_COST,
        parallelism=PARALLELISM,
        hash_len=AES_KEY_SIZE,
        salt=salt
    )
    return kdf.derive(password.encode())


def encrypt_shamir_message(message: str, key: bytes) -> tuple[str, str, str]:
    """
    Encrypt a message using AES-GCM.

    Args:
        message (str): The message to encrypt.
        key (bytes): The AES key.

    Returns:
        tuple: A tuple containing the encrypted message, the IV, and the authentication tag in hexadecimal format.
    """
    iv = secrets.token_bytes(AES_IV_SIZE)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(message.encode()) + encryptor.finalize()
    return encrypted_message.hex(), iv.hex(), encryptor.tag.hex()


def decrypt_shamir_message(encrypted_message: str, key: bytes, iv: str, tag: str) -> str:
    """
    Decrypt an encrypted message using AES-GCM.

    Args:
        encrypted_message (str): The encrypted message in hexadecimal format.
        key (bytes): The AES key.
        iv (str): The IV in hexadecimal format.
        tag (str): The authentication tag in hexadecimal format.

    Returns:
        str: The decrypted message.
    """
    cipher = Cipher(algorithms.AES(key), modes.GCM(bytes.fromhex(iv), bytes.fromhex(tag)), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(bytes.fromhex(encrypted_message)) + decryptor.finalize()
    return decrypted_message.decode()


# Example usage
if __name__ == "__main__":
    password = "Secure_Password123!"
    salt = generate_shannon_salt()
    hashed_password, salt_hex = hash_turing_password(password, salt)

    logger.info(f"Hashed Password: {hashed_password}")
    logger.info(f"Salt: {salt_hex}")

    # Verify the password
    is_valid = verify_diffie_password(hashed_password, salt_hex, password)
    logger.info(f"Password is valid: {is_valid}")

    # Encrypt a message
    message = "This is a secure message."
    aes_key = derive_rivest_key(password, salt)
    encrypted_message, iv_hex, tag_hex = encrypt_shamir_message(message, aes_key)
    logger.info(f"Encrypted Message: {encrypted_message}")
    logger.info(f"IV: {iv_hex}")
    logger.info(f"Tag: {tag_hex}")

    # Decrypt the message
    decrypted_message = decrypt_shamir_message(encrypted_message, aes_key, iv_hex, tag_hex)
    logger.info(f"Decrypted Message: {decrypted_message}")
