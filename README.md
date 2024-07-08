# 🔐 Skygen Enigma

Welcome to **Skygen Enigma**! This project is your ultimate cryptographic toolkit, inspired by the giants of cryptography. Whether you're looking to hash passwords, encrypt messages, or just dive into the world of secure coding, Skygen Enigma has got you covered.

## 🚀 Features

- **Strong Password Hashing**: Utilizes Argon2 and SHA-3 for robust password hashing.
- **Secure Encryption**: Encrypt and decrypt messages using AES-GCM.
- **Cool Function Names**: Functions named after famous cryptographers to make your coding experience more fun!

## 🛠️ Installation

Clone the repository and install the required packages:

```bash
git clone https://github.com/yourusername/skygen_enigma.git
cd skygen_enigma
pip install -r requirements.txt

## 🚦 Usage
Here's how you can use Skygen Enigma in your project:

## Hashing a Password
from skygen_enigma import generate_shannon_salt, hash_turing_password

password = "Secure_Password123!"
salt = generate_shannon_salt()
hashed_password, salt_hex = hash_turing_password(password, salt)

print(f"Hashed Password: {hashed_password}")
print(f"Salt: {salt_hex}")

## Verifying a Password
from skygen_enigma import verify_diffie_password

is_valid = verify_diffie_password(hashed_password, salt_hex, password)
print(f"Password is valid: {is_valid}")

## Encrypting a Message

from skygen_enigma import derive_rivest_key, encrypt_shamir_message

message = "This is a secure message."
aes_key =
