from pqcrypto.kem import kyber

class PostQuantumCryptography:
    @staticmethod
    def pq_encrypt(data, public_key):
        ciphertext, shared_secret = kyber.encrypt(public_key, data)
        return ciphertext, shared_secret

    @staticmethod
    def pq_decrypt(ciphertext, private_key):
        data = kyber.decrypt(private_key, ciphertext)
        return data
