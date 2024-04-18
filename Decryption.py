import os
import tkinter as tk
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.primitives import hmac, hashes
from cryptography.hazmat.backends import default_backend
from Crypto.Util.Padding import unpad
from Crypto.Cipher import AES, DES3
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES, AES128, AES256
from re import I
from tkinter import messagebox
import json

'''Derive master key from the password entered by user.'''
def derive_masterkey(pwd, salt, iteration_count, hashing_algo, encryption_algo):
    passwd = pwd.encode("utf8")
    salt = bytes.fromhex(salt)
    
    if "256" in hashing_algo:
        if "TripleDES" in encryption_algo:
            key_len = 24
        elif "AES128" in encryption_algo:
            key_len = 16

        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=key_len, salt=salt, iterations=iteration_count,)
    elif "512" in hashing_algo:
        key_len = 32
        kdf = PBKDF2HMAC(algorithm=hashes.SHA512(), length=key_len, salt=salt, iterations=iteration_count,)

    master_key = kdf.derive(passwd)
    return master_key, key_len

'''Derive the HMAC key from the master key derived in previous step'''
def derive_kh(master_key, hashing_algo, key_len):
    salt = ('Hmackey').encode('utf8')
    iterations = 1
    if "256" in hashing_algo:
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=key_len, salt=salt, iterations=1,)
    elif "512" in hashing_algo:
        kdf = PBKDF2HMAC(algorithm=hashes.SHA512(), length=key_len, salt=salt, iterations=1,)

    HMAC_key = kdf.derive(master_key)
    return HMAC_key

'''Derive the encryption key based on the master key derived in previous step'''
def derive_ke(master_key, hashing_algo, key_len):
  iterations = 1
  salt = ('hashing').encode('utf8')
  if "256" in hashing_algo:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=key_len, salt=salt, iterations=1,)

  elif "512" in hashing_algo:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA512(), length=key_len, salt=salt, iterations=1,)

  enc_key = kdf.derive(master_key)
  return enc_key

'''Using the encrypted hmac of the data received from the encrypted file, derive the iv, cipher text to decrypt and the hmac from encrypted file. Once all this information is available,
compute hmac and then compare with received hmac to see if they are same or different'''
def decrypt_with_hmac(encrypted_data_with_hmac, encryption_algo, kh):
    # Extract IV, ciphertext, and HMAC tag
    iv_length = 16 if "AES" in encryption_algo else 8
    iv = encrypted_data_with_hmac[:iv_length]
    ciphertext = encrypted_data_with_hmac[iv_length:-32]
    received_hmac = encrypted_data_with_hmac[-32:] 
    
    # Compute HMAC tag using IV and ciphertext
    hmac_tag = hmac.HMAC(kh, hashes.SHA256(), backend=default_backend())
    hmac_tag.update(iv + ciphertext)
    computed_hmac = hmac_tag.finalize()

    # Verify HMAC tag
    if computed_hmac != received_hmac:
        #messagebox.showinfo("Error","HMAC validation failed. The file may have been tampered with.")
        return False, False
    else:
        #messagebox.showinfo("Update","HMAC validation sucessful, decryption successful.")
        return (iv, ciphertext)
    
#Using the above information, decrypt the cipher text 
def decrypt_with_algorithm(encryption_algo, ciphertext, ke, iv, file_path):
    try:
        if "AES128" in encryption_algo:
            cipher = AES.new(ke, AES.MODE_CBC, iv)
            block_size = 16  # AES block size is always 16 bytes
        elif "AES256" in encryption_algo:
            cipher = AES.new(ke, AES.MODE_CBC, iv)
            block_size = 32  # AES256 block size is 32 bytes
        elif "TripleDES" in encryption_algo:
            cipher = DES3.new(ke, DES3.MODE_CBC, iv)
            block_size = 8  # TripleDES block size is 8 bytes
        else:
            raise ValueError("Unsupported encryption algorithm")

        # Decrypt the ciphertext
        decrypted_data = cipher.decrypt(ciphertext)

        # Unpad the decrypted data
        plaintext = unpad(decrypted_data, block_size)
        print("plain text: ", plaintext)
        
        directory, filename = os.path.split(file_path)
        output_file_path = os.path.join(directory, f"decrypted_{filename}.txt")
        
        if output_file_path:
            with open(output_file_path, 'wb') as output_file:
                output_file.write(plaintext)
        return True
    
    except Exception as e:
        print(e)
        return False

# Function to read metadata from JSON file
def read_metadata_from_json(file_name):
    current_directory = os.getcwd()
    file_path = os.path.join(current_directory, file_name)
    with open(file_path, "r") as file:
        metadata = json.load(file)
    return metadata


