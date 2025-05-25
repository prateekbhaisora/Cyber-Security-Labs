import time
import os, secrets, string
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives import hmac, hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import padding as pdd
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

SEP = '-' * 150

class ExecuteCrypto(object): 

    def generate_symmetric_key(self, length):
        alphabet = string.ascii_letters + string.digits
        return ''.join(secrets.choice(alphabet) for _ in range(length))
    
    def generate_keys(self):
        """Generate keys"""

        symmetric_key = self.generate_symmetric_key(16)
        private_key_sender_rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key_sender_rsa = private_key_sender_rsa.public_key()
        private_key_receiver_rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key_receiver_rsa = private_key_receiver_rsa.public_key()
        private_key_sender_ecc=  ec.generate_private_key(ec.SECP256R1()) 
        public_key_sender_ecc = private_key_sender_ecc.public_key()

        symmetric_key = symmetric_key.encode('utf-8')

        print(SEP)
        print("Symmetric Key") 
        print(symmetric_key) 
        print(SEP)
        
        print(SEP)
        print("Sender's RSA Public Key") 
        public_key_sender_rsa_pem = public_key_sender_rsa.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        print(public_key_sender_rsa_pem.decode(), end="")
        print(SEP)
        
        print("Sender's RSA Private Key") 
        private_key_sender_rsa_pem = private_key_sender_rsa.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,  
            encryption_algorithm=serialization.NoEncryption()       
        )
        print(private_key_sender_rsa_pem.decode(), end="")
        print(SEP)
        
        print(SEP)
        print("Receiver's RSA Public Key") 
        public_key_receiver_rsa_pem = public_key_receiver_rsa.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        print(public_key_receiver_rsa_pem.decode(), end="")
        print(SEP)
        
        print(SEP)
        print("Receiver's RSA Private Key")
        private_key_receiver_rsa_pem = private_key_receiver_rsa.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,  
            encryption_algorithm=serialization.NoEncryption()       
        )
        print(private_key_receiver_rsa_pem.decode(), end="")  
        print(SEP)
        
        print(SEP)
        print("Sender's ECC Public Key")
        public_key_sender_ecc_pem = public_key_sender_ecc.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        print(public_key_sender_ecc_pem.decode(), end="")
        print(SEP)
        
        print(SEP)
        print("Sender's ECC Private Key") 
        private_key_sender_ecc_pem = private_key_sender_ecc.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        print(private_key_sender_ecc_pem.decode(), end="")
        print(SEP)

        return symmetric_key, \
                public_key_sender_rsa, private_key_sender_rsa, \
                public_key_receiver_rsa, private_key_receiver_rsa, \
                public_key_sender_ecc, private_key_sender_ecc 

    def generate_nonces(self):
        """Generate nonces"""

        nonce_aes_cbc = os.urandom(16)  
        nonce_aes_ctr = os.urandom(16)  
        nonce_encrypt_rsa = os.urandom(16)  
        nonce_aes_cmac = os.urandom(16)  
        nonce_hmac = os.urandom(16)  
        nonce_tag_rsa = os.urandom(16) 
        nonce_ecdsa = os.urandom(32)  
        nonce_aes_gcm = os.urandom(12) 

        print(SEP)
        print("Nonce for AES-128-CBC") 
        print(nonce_aes_cbc) 
        print(SEP)
        
        print(SEP)
        print("Nonce for AES-128-CTR") 
        print(nonce_aes_ctr) 
        print(SEP)
        
        print(SEP)
        print("Nonce for RSA-2048") 
        print(nonce_encrypt_rsa) 
        print(SEP)
        
        print(SEP)
        print("Nonce for AES-128-CMAC") 
        print(nonce_aes_cmac) 
        print(SEP)
        
        print(SEP)
        print("Nonce for SHA3-256-HMAC") 
        print(nonce_hmac) 
        print(SEP)
        
        print(SEP)
        print("Nonce for RSA-2048-SHA3-256") 
        print(nonce_tag_rsa) 
        print(SEP)
        
        print(SEP)
        print("Nonce for ECDSA") 
        print(nonce_ecdsa) 
        print(SEP)
        
        print(SEP)
        print("Nonce for AES-128-GCM") 
        print(nonce_aes_gcm) 
        print(SEP)

        return nonce_aes_cbc, nonce_aes_ctr, nonce_encrypt_rsa, nonce_aes_cmac, \
                nonce_hmac, nonce_tag_rsa, nonce_ecdsa, nonce_aes_gcm 

    def encrypt(self, algo, key, plaintext, nonce): 
        """Encrypt the given plaintext"""

        ciphertext = b""

        if algo == 'AES-128-CBC-ENC': 
            padder = pdd.PKCS7(128).padder()
            plaintext = plaintext.encode('utf-8')
            padded_plaintext = padder.update(plaintext) + padder.finalize()
            cipher = Cipher(algorithms.AES(key), modes.CBC(nonce))
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
            plaintext = plaintext.decode('utf-8')

        elif algo == 'AES-128-CTR-ENC': 
            plaintext = plaintext.encode('utf-8')
            cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()
            plaintext = plaintext.decode('utf-8')

        elif algo == 'RSA-2048-ENC': 
            ciphertext = key.encrypt(plaintext, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
            plaintext = plaintext.decode('utf-8')

        else: 
            raise Exception("Unexpected algorithm") 

        print(SEP)
        print("Algorithm") 
        print(algo) 
        print("Encryption Key") 
        print(key) 
        print("Plaintext") 
        print(plaintext) 
        print("Nonce") 
        print(nonce) 
        print("Ciphertext") 
        print(ciphertext) 
        print(SEP)

        return ciphertext 

    def decrypt(self, algo, key, ciphertext, nonce, public_key=None): 
        """Decrypt the given ciphertext"""
        plaintext = ""

        if algo == 'AES-128-CBC-DEC': 
            cipher = Cipher(algorithms.AES(key), modes.CBC(nonce))
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
            unpadder = pdd.PKCS7(128).unpadder()
            plaintext = unpadder.update(decrypted_data) + unpadder.finalize()
            plaintext = plaintext.decode('utf-8')

        elif algo == 'AES-128-CTR-DEC': 
            cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            plaintext = plaintext.decode('utf-8')

        elif algo == 'RSA-2048-DEC': 
            plaintext = key.decrypt(ciphertext, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
            plaintext = plaintext.decode('utf-8')

        else: 
            raise Exception("Unexpected algorithm") 

        print(SEP)
        print("Algorithm") 
        print(algo) 
        print("Decryption Key") 
        print(key) 
        print("Plaintext") 
        print(plaintext) 
        print("Nonce") 
        print(nonce) 
        print("Ciphertext") 
        print(ciphertext) 
        print(SEP)
        
        return plaintext 

    def generate_auth_tag(self, algo, key, plaintext, nonce): 
        """Generate the authenticate tag for the given plaintext"""

        auth_tag = ""

        if algo =='AES-128-CMAC-GEN': 
            plaintext = plaintext.encode('utf-8')
            cipher = CMAC(algorithms.AES(key))
            cipher.update(plaintext)
            auth_tag = cipher.finalize()
            plaintext = plaintext.decode('utf-8')

        elif algo =='SHA3-256-HMAC-GEN': 
            plaintext = plaintext.encode('utf-8')
            hmac_key = key 
            h = hmac.HMAC(hmac_key, hashes.SHA3_256())
            h.update(plaintext)
            auth_tag = h.finalize()
            plaintext = plaintext.decode('utf-8')

        elif algo =='RSA-2048-SHA3-256-SIG-GEN': 
            plaintext = plaintext.encode('utf-8')
            signature = key.sign(plaintext, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
            auth_tag = signature
            plaintext = plaintext.decode('utf-8')

        elif algo =='ECDSA-256-SHA3-256-SIG-GEN': 
            plaintext = plaintext.encode('utf-8')
            signature = key.sign(plaintext, ec.ECDSA(hashes.SHA3_256()))
            auth_tag = signature
            plaintext = plaintext.decode('utf-8')

        else:
            raise Exception("Unexpected algorithm") 

        print(SEP)
        print("Algorithm") 
        print(algo) 
        print("Authentication Key") 
        print(key) 
        print("Plaintext") 
        print(plaintext) 
        print("Nonce") 
        print(nonce) 
        print("Authentication Tag") 
        print(auth_tag) 
        print(SEP)

        return auth_tag 

    def verify_auth_tag(self, algo, key, plaintext, nonce, auth_tag): 
        """Verify the authenticate tag for the given plaintext"""
        
        auth_tag_valid = ""

        if algo =='AES-128-CMAC-VRF': 
            plaintext = plaintext.encode('utf-8')
            cipher = CMAC(algorithms.AES(key))
            cipher.update(plaintext)
            try:
                cipher.verify(auth_tag)
                auth_tag_valid = "Valid"
            except:
                auth_tag_valid = "Invalid"
            plaintext = plaintext.decode('utf-8')

        elif algo =='SHA3-256-HMAC-VRF': 
            plaintext = plaintext.encode('utf-8')
            hmac_key = key  
            h = hmac.HMAC(hmac_key, hashes.SHA3_256())
            h.update(plaintext)
            try:
                h.verify(auth_tag)
                auth_tag_valid = "Valid"
            except:
                auth_tag_valid = "Invalid"
            plaintext = plaintext.decode('utf-8')

        elif algo =='RSA-2048-SHA3-256-SIG-VRF': 
            plaintext = plaintext.encode('utf-8')
            try:
                key.verify(auth_tag, plaintext, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
                auth_tag_valid = "Valid"
            except:
                auth_tag_valid = "Invalid"
            plaintext = plaintext.decode('utf-8')

        elif algo =='ECDSA-256-SHA3-256-SIG-VRF': 
            plaintext = plaintext.encode('utf-8')
            public_key = key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
            try:
                public_key.verify(auth_tag, plaintext, ec.ECDSA(hashes.SHA3_256()))
                auth_tag_valid = "Valid"
            except:
                auth_tag_valid = "Valid"
            plaintext = plaintext.decode('utf-8')

        else:
            raise Exception("Unexpected algorithm") 

        print(SEP)
        print("Algorithm") 
        print(algo) 
        print("Authentication Key") 
        print(key) 
        print("Plaintext") 
        print(plaintext) 
        print("Nonce") 
        print(nonce) 
        print("Authentication Tag") 
        print(auth_tag) 
        print("Authentication Tag Valid") 
        print(auth_tag_valid) 
        print(SEP)

        return auth_tag_valid 

    def encrypt_generate_auth(self, algo, key_encrypt, key_generate_auth, plaintext, nonce): 
        """Encrypt and generate the authentication tag for the given plaintext"""

        ciphertext = b""
        auth_tag = b""

        if algo == 'AES-128-GCM-GEN': 
            plaintext = plaintext.encode('utf-8')
            cipher = Cipher(algorithms.AES(key_encrypt), modes.GCM(nonce))
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()
            auth_tag = encryptor.tag
            plaintext = plaintext.decode('utf-8')

        else:
            raise Exception("Unexpected algorithm") 

        print(SEP)
        print("Algorithm") 
        print(algo) 
        print("Encryption Key") 
        print(key_encrypt) 
        print("Authentication Key") 
        print(key_generate_auth) 
        print("Plaintext") 
        print(plaintext) 
        print("Nonce") 
        print(nonce) 
        print("Ciphertext") 
        print(ciphertext) 
        print("Authentication Tag") 
        print(auth_tag) 
        print(SEP)

        return ciphertext, auth_tag 

    def decrypt_verify_auth(self, algo, key_decrypt, key_verify_auth, ciphertext, nonce, auth_tag): 
        """Decrypt and verify the authentication tag for the given plaintext"""

        plaintext = b""
        auth_tag_valid = ""

        if algo == 'AES-128-GCM-VRF': 
            cipher = Cipher(algorithms.AES(key_decrypt), modes.GCM(nonce, auth_tag))
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            try:
                decryptor.verify(auth_tag)
                auth_tag_valid = "Valid"
            except Exception as e:
                auth_tag_valid = "Valid"
            plaintext = plaintext.decode('utf-8')

        else:
            raise Exception("Unexpected algorithm") 

        print(SEP)
        print("Algorithm") 
        print(algo) 
        print("Decryption Key") 
        print(key_decrypt) 
        print("Authentication Key") 
        print(key_verify_auth) 
        print("Plaintext") 
        print(plaintext) 
        print("Nonce") 
        print(nonce) 
        print("Ciphertext") 
        print(ciphertext) 
        print("Authentication Tag") 
        print(auth_tag) 
        print("Authentication Tag Valid") 
        print(auth_tag_valid) 
        print(SEP)

        return plaintext, auth_tag_valid 

if __name__ == '__main__': 
    ExecuteCrypto() 