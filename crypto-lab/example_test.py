import rsa
import time
from execute_crypto import ExecuteCrypto
from cryptography.hazmat.primitives import serialization

def read_plaintext_from_file(filename):
    with open(filename, 'r') as file:
        plaintext = file.read()
    return plaintext

def main():
    obj = ExecuteCrypto()

    symmetric_key, \
    public_key_sender_rsa, private_key_sender_rsa, \
    public_key_receiver_rsa, private_key_receiver_rsa, \
    public_key_sender_ecc, private_key_sender_ecc = obj.generate_keys()

    nonce_aes_cbc, nonce_aes_ctr, nonce_encrypt_rsa, nonce_aes_cmac, \
    nonce_hmac, nonce_tag_rsa, nonce_ecdsa, nonce_aes_gcm = obj.generate_nonces()

    plaintext = read_plaintext_from_file("original_plaintext.txt")
    
    start_time = time.perf_counter()
    ciphertext_aes_cbc = obj.encrypt("AES-128-CBC-ENC", symmetric_key, plaintext, nonce_aes_cbc)
    end_time = time.perf_counter()
    print("Plaintext size: ", len(plaintext) * 8)
    print("Ciphertext size: ", len(ciphertext_aes_cbc) * 8)
    execution_time = (end_time - start_time) * 1000
    print("Execution time:", execution_time, "milliseconds")
    
    start_time = time.perf_counter()
    decrypted_text_aes_cbc = obj.decrypt("AES-128-CBC-DEC", symmetric_key, ciphertext_aes_cbc, nonce_aes_cbc)
    end_time = time.perf_counter()
    execution_time = (end_time - start_time) * 1000
    print("Execution time:", execution_time, "milliseconds")

    start_time = time.perf_counter()
    ciphertext_aes_ctr = obj.encrypt("AES-128-CTR-ENC", symmetric_key, plaintext, nonce_aes_ctr)
    end_time = time.perf_counter()
    print("Plaintext size: ", len(plaintext) * 8)
    print("Ciphertext size: ", len(ciphertext_aes_ctr) * 8)
    execution_time = (end_time - start_time) * 1000
    print("Execution time:", execution_time, "milliseconds")

    start_time = time.perf_counter()
    decrypted_text_aes_ctr = obj.decrypt("AES-128-CTR-DEC", symmetric_key, ciphertext_aes_ctr, nonce_aes_ctr)
    end_time = time.perf_counter()
    execution_time = (end_time - start_time) * 1000
    print("Execution time:", execution_time, "milliseconds")

    start_time = time.perf_counter()
    ciphertext_rsa = obj.encrypt("RSA-2048-ENC", public_key_receiver_rsa, symmetric_key, nonce_encrypt_rsa)
    end_time = time.perf_counter()
    print("Plaintext size: ", len(plaintext) * 8)
    print("Ciphertext size: ", len(ciphertext_rsa) * 8)
    execution_time = (end_time - start_time) * 1000
    print("Execution time:", execution_time, "milliseconds")

    start_time = time.perf_counter()
    decrypted_text_rsa = obj.decrypt("RSA-2048-DEC", private_key_receiver_rsa, ciphertext_rsa, nonce_encrypt_rsa)
    end_time = time.perf_counter()
    execution_time = (end_time - start_time) * 1000
    print("Execution time:", execution_time, "milliseconds")

    start_time = time.perf_counter()
    auth_tag_aes_cmac = obj.generate_auth_tag("AES-128-CMAC-GEN", symmetric_key, plaintext, nonce_aes_cmac)
    end_time = time.perf_counter()
    print("Plaintext size: ", len(plaintext) * 8)
    print("Tag size: ", len(auth_tag_aes_cmac) * 8)
    execution_time = (end_time - start_time) * 1000
    print("Execution time:", execution_time, "milliseconds")

    start_time = time.perf_counter()
    auth_tag_valid_aes_cmac = obj.verify_auth_tag("AES-128-CMAC-VRF", symmetric_key, plaintext, nonce_aes_cmac, auth_tag_aes_cmac)
    end_time = time.perf_counter()
    execution_time = (end_time - start_time) * 1000
    print("Execution time:", execution_time, "milliseconds")

    start_time = time.perf_counter()
    auth_tag_hmac = obj.generate_auth_tag("SHA3-256-HMAC-GEN", symmetric_key, plaintext, nonce_hmac)
    end_time = time.perf_counter()
    print("Plaintext size: ", len(plaintext) * 8)
    print("Tag size: ", len(auth_tag_hmac) * 8)
    execution_time = (end_time - start_time) * 1000
    print("Execution time:", execution_time, "milliseconds")

    start_time = time.perf_counter()
    auth_tag_valid_hmac = obj.verify_auth_tag("SHA3-256-HMAC-VRF", symmetric_key, plaintext, nonce_hmac, auth_tag_hmac)
    end_time = time.perf_counter()
    execution_time = (end_time - start_time) * 1000
    print("Execution time:", execution_time, "milliseconds")

    start_time = time.perf_counter()
    auth_tag_rsa = obj.generate_auth_tag("RSA-2048-SHA3-256-SIG-GEN", private_key_sender_rsa, plaintext, nonce_tag_rsa)
    end_time = time.perf_counter()
    print("Plaintext size: ", len(plaintext) * 8)
    print("Tag size: ", len(auth_tag_rsa) * 8)
    execution_time = (end_time - start_time) * 1000
    print("Execution time:", execution_time, "milliseconds")

    start_time = time.perf_counter()
    auth_tag_valid_rsa = obj.verify_auth_tag("RSA-2048-SHA3-256-SIG-VRF", public_key_sender_rsa, plaintext, nonce_tag_rsa, auth_tag_rsa)
    end_time = time.perf_counter()
    execution_time = (end_time - start_time) * 1000
    print("Execution time:", execution_time, "milliseconds")

    start_time = time.perf_counter()
    auth_tag_ecdsa = obj.generate_auth_tag("ECDSA-256-SHA3-256-SIG-GEN", private_key_sender_ecc, plaintext, nonce_ecdsa)
    end_time = time.perf_counter()
    print("Plaintext size: ", len(plaintext) * 8)
    print("Tag size: ", len(auth_tag_ecdsa) * 8)
    execution_time = (end_time - start_time) * 1000
    print("Execution time:", execution_time, "milliseconds")

    start_time = time.perf_counter()
    auth_tag_valid_ecdsa = obj.verify_auth_tag("ECDSA-256-SHA3-256-SIG-VRF", public_key_sender_ecc, plaintext, nonce_ecdsa, auth_tag_ecdsa)
    end_time = time.perf_counter()
    execution_time = (end_time - start_time) * 1000
    print("Execution time:", execution_time, "milliseconds")

    start_time = time.perf_counter()
    ciphertext_aes_gcm, auth_tag_aes_gcm = obj.encrypt_generate_auth("AES-128-GCM-GEN", symmetric_key, symmetric_key, plaintext, nonce_aes_gcm)
    end_time = time.perf_counter()
    print("Plaintext size: ", len(plaintext) * 8)
    print("Ciphertext size: ", len(ciphertext_aes_gcm) * 8)
    print("Tag size: ", len(ciphertext_aes_gcm) * 8) 
    execution_time = (end_time - start_time) * 1000
    print("Execution time:", execution_time, "milliseconds")    

    start_time = time.perf_counter()
    decrypted_text_aes_gcm, auth_tag_valid_aes_gcm = obj.decrypt_verify_auth("AES-128-GCM-VRF", symmetric_key, symmetric_key, ciphertext_aes_gcm, nonce_aes_gcm, auth_tag_aes_gcm)
    end_time = time.perf_counter()
    execution_time = (end_time - start_time) * 1000
    print("Execution time:", execution_time, "milliseconds")

if __name__ == '__main__':
    main()
