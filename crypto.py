from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives import padding as symPadd
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from os.path import join, exists
import os


class CrModule:
    def __init__(self):
        self.keys = {}
        pass

    def encrypt(self, file):
        if 'private' not in self.keys:
            print("Encryption error, user not logged in")
            return
        elif not file:
            print("Error while encrypting, invalid file")
            return

        sig = self.keys['private'].sign(
            file,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256())

        file = file + sig

        key = os.urandom(32)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        padder = symPadd.PKCS7(128).padder()
        file = padder.update(file) + padder.finalize()
        file = cipher.encryptor().update(file) + cipher.encryptor().finalize()
        symKey = key + iv
        symKey = self.keys['public'].encrypt(
            symKey,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None)
        )
        return file + symKey

    def decrypt(self, file):
        if 'private' not in self.keys:
            print("Decryption error, user not logged in")
            return
        elif not file:
            print("Error while decrypting, invalid file")
            return

        symKey = file[len(file) - 256:]
        file = file[:len(file) - 256]

        symKey = self.keys['private'].decrypt(
            symKey,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            ))

        key, iv = symKey[:32], symKey[32:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        file = cipher.decryptor().update(file) + cipher.decryptor().finalize()
        unpadder = symPadd.PKCS7(128).unpadder()
        file = unpadder.update(file) + unpadder.finalize()

        sig = file[len(file) - 256:]
        file = file[:len(file) - 256]

        try:
            self.keys['public'].verify(
                sig,
                file,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256())
        except InvalidSignature:
            print("Error while decrypting the file, signature error")
            return
        return file

    def reg(self, password):
        self.keys['private'] = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.keys['public'] = self.keys['private'].public_key()

        if not exists("Keys"):
            os.mkdir("Keys")

        with open(join("Keys", "pass.bin"), "wb") as file:
            file.write(self.keys['public'].encrypt(
                password.encode('ascii'),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None)
            ))

        with open(join("Keys", "private.pem"), "wb") as file:
            file.write(self.keys['private'].private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(password.encode('ascii'))
            ))

        with open(join("Keys", "public.pem"), "wb") as file:
            file.write(self.keys['public'].public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

        print("New password registered correctly")

    def auth(self, password):
        if not exists("Keys") or not exists(join("Keys", "pass.bin")):
            print("Could not log in, no password registered")
            return False
        try:
            with open(join("Keys", "private.pem"), "rb") as file:
                self.keys['private'] = serialization.load_pem_private_key(file.read(), password=password.encode('ascii'))
        except ValueError:
            print("Error logging in, wrong password")
            return False

        with open(join("Keys", "pass.bin"), "rb") as file:
            passwordFile = self.keys['private'].decrypt(
                file.read(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        if password != passwordFile.decode("ascii"):
            print("Error logging in, wrong password")
            return False

        with open(join("Keys", "public.pem"), "rb") as file:
            self.keys['public'] = serialization.load_pem_public_key(file.read())

        print("Logged in correctly")
        return True
