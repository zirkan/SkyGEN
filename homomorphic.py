from phe import paillier

class HomomorphicEncryption:
    @staticmethod
    def he_encrypt(data, public_key):
        encrypted_data = public_key.encrypt(data)
        return encrypted_data

    @staticmethod
    def he_decrypt(encrypted_data, private_key):
        decrypted_data = private_key.decrypt(encrypted_data)
        return decrypted_data
