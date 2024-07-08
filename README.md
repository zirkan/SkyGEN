# 🔐 SkyGen Enigma: Ultimate Password Hashing & Encryption Toolkit

Welcome to **SkyGen Enigma**, your go-to toolkit for state-of-the-art password hashing and encryption! Whether you're a developer looking to secure user passwords or just someone who loves cryptography, SkyGen Enigma has got you covered.

## 🚀 Features

- **Argon2 Password Hashing**: Leverage the power of Argon2, the winner of the Password Hashing Competition, for robust password security.
- **SHA-3 Hashing**: Add an extra layer of security with SHA-3 hashing.
- **AES-GCM Encryption**: Secure your data with AES-GCM, ensuring both confidentiality and integrity.
- **Strong Password Policy Enforcement**: Enforce strong passwords with checks for length, digits, upper and lower case letters, and special characters.
- **Comprehensive Logging**: Keep track of all operations with detailed logging.
- **Environment Configurable**: Easily tweak settings with environment variables.

## ⚖️ Why SkyGen Enigma?

### Superior Security Methods

1. **Argon2 Password Hashing**:
   - **Memory-Hard Function**: Argon2 is designed to resist brute-force attacks by requiring significant memory to compute, making it costly for attackers.
   - **Winner of the Password Hashing Competition**: This endorsement ensures that Argon2 has been rigorously tested and vetted by cryptography experts.

2. **SHA-3 Hashing**:
   - **NIST Standard**: SHA-3 is the latest member of the Secure Hash Algorithm family and provides a robust hashing mechanism that is resistant to all known attacks.
   - **Future-Proof**: With its strong security guarantees, SHA-3 is designed to be secure for the foreseeable future.

3. **AES-GCM Encryption**:
   - **Authenticated Encryption**: AES-GCM not only encrypts your data but also ensures its integrity and authenticity, protecting against tampering.
   - **Widely Adopted**: AES-GCM is used in many modern security protocols, including TLS and IPsec, due to its efficiency and security.

### Strong Password Policy

- **Enforcement of Best Practices**: By requiring passwords to have a mix of characters and a minimum length, SkyGen Enigma ensures that users create strong passwords that are harder to crack.

### Comprehensive Logging

- **Detailed Logs**: Keep track of all operations, making it easier to debug issues and monitor the security of your application.

### Environment Configurable

- **Flexible Configuration**: Easily adjust the security parameters to suit your specific needs and environment.

## 📦 Installation

Clone the repository and navigate to the project directory:

```bash
git clone git@github.com:zirkan/SkyGEN.git
cd SkyGEN
```

Install the required dependencies:

```bash
pip install -r requirements.txt
```

## 🛠️ Usage

Here's a quick guide to get you started with SkyGen Enigma:

### 1. Hash a Password

```python
from skygen_enigma import generate_shannon_salt, hash_turing_password

password = "SuperSecurePassword123!"
salt = generate_shannon_salt()
hashed_password, salt_hex = hash_turing_password(password, salt)

print(f"Hashed Password: {hashed_password}")
print(f"Salt: {salt_hex}")
```

### 2. Verify a Password

```python
from skygen_enigma import verify_diffie_password

is_valid = verify_diffie_password(password, hashed_password, bytes.fromhex(salt_hex))

if is_valid:
    print("Password is valid!")
else:
    print("Invalid password.")
```

### 3. Encrypt Data

```python
from skygen_enigma import encrypt_data, decrypt_data

data = b"Sensitive data that needs encryption"
key = b"32_byte_key_for_aes_gcm_"  # Ensure your key is 32 bytes
iv, ciphertext, tag = encrypt_data(data, key)

print(f"IV: {iv}")
print(f"Ciphertext: {ciphertext}")
print(f"Tag: {tag}")

# Decrypt the data
decrypted_data = decrypt_data(iv, ciphertext, tag, key)
print(f"Decrypted Data: {decrypted_data}")
```

## ⚙️ Configuration

You can configure the Argon2 parameters using environment variables:

```bash
export ARGON2_TIME_COST=3
export ARGON2_MEMORY_COST=65536
export ARGON2_PARALLELISM=4
```

## 🧪 Testing

Run the tests to ensure everything is working correctly:

```bash
pytest
```

## 🤝 Contributing

We welcome contributions! Feel free to fork the repository, make your changes, and submit a pull request.

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## 🌟 Acknowledgements

- [Argon2](https://github.com/P-H-C/phc-winner-argon2)
- [Cryptography](https://github.com/pyca/cryptography)
- [Python HMAC](https://docs.python.org/3/library/hmac.html)

## 🚀 Let's Get Secure!

Join us in making the web a safer place, one hash at a time. Happy coding! 🎉
