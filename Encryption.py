import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import hashlib
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes
from cryptography.hazmat.primitives import hmac, hashes
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES, DES3
from Crypto.Util.Padding import pad
from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES, AES128, AES256
from re import I
import json

#create a master key using PBKDF2
'''
The function PBKDF2HMAC from python's inbuilt library is used below. This function takes in the password, salt, hashing algorithm, number of iterations and the key length as input.

'''
def derive_master_key(hashing_algo, pwd, salt, iterations, key_len):
  passwd = pwd.encode("utf8")
  
  if "256" in hashing_algo:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=key_len, salt=salt, iterations=iterations,)

  elif "512" in hashing_algo:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA512(), length=key_len, salt=salt, iterations=iterations,)

  key = kdf.derive(passwd)
  return key

'''Derive an encryption key with iteration count set to 1. The salt value used for the encryption key is fixed and hard-coded below.'''
def derive_encryption_key(master_key, cipher_suite, choice, key_length):
  iterations = 1
  hashing_algo = cipher_suite[choice][0]
  salt = ('hashing').encode('utf8')
  if "256" in hashing_algo:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=key_length, salt=salt, iterations=1,)

  elif "512" in hashing_algo:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA512(), length=key_length, salt=salt, iterations=1,)

  enc_key = kdf.derive(master_key)
  return enc_key

'''Derive an HMAC key with iteration count set to 1. The salt value used for deriving the HMAC key is fixed and hard coded below.'''
def derive_HMAC_key(master_key, cipher_suite, choice , key_len):
  iterations = 1
  hashing_algo = cipher_suite[choice][0]
  salt = ('Hmackey').encode('utf8')
  if "256" in hashing_algo:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=key_len, salt=salt, iterations=1,)

  elif "512" in hashing_algo:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA512(), length=key_len, salt=salt, iterations=1,)

  HMAC_key = kdf.derive(master_key)
  return HMAC_key


#Encrypt the data with encrypted key and the initialization vector. The iv is created randomly and the number of bytes depend on which algorithm is selected by user.
def encrypt_with_algorithm(cipher_suite, choice, file_content, encryption_key):
  plaintext = file_content
  encryption_algo = str(cipher_suite[choice][1])
  
  # Define the IV (Initialization Vector)
  if "AES" in encryption_algo:
      iv = os.urandom(16)  # For AES, IV size is 16 bytes
  else:
      iv = os.urandom(8)   # For TripleDES, IV size is 8 bytes

  # Create a cipher object with the specified algorithm in CBC mode
  if "AES128" in encryption_algo:
      cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
      algorithm = algorithms.AES(encryption_key)  
      block_size = 16  # AES block size is always 16 bytes
  elif "AES256" in encryption_algo:
      cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
      algorithm = algorithms.AES(encryption_key)
      block_size = 32  # AES256 block size is 32 bytes
  elif "TripleDES" in encryption_algo:
      cipher = DES3.new(encryption_key, DES3.MODE_CBC, iv)
      algorithm = algorithms.TripleDES(encryption_key)
      block_size = 8  # TripleDES block size is 8 bytes
  else:
      raise ValueError("Unsupported encryption algorithm")

  # Pad the plaintext with zeros
  padded_plaintext = pad(plaintext, block_size)

  # Encrypt the padded plaintext
  ciphertext = cipher.encrypt(padded_plaintext)

  return ciphertext, iv


#create HMAC with the HMAC key, covering both IV and the encrypted data
def last_step_encryption(kh, cipher_text, iv):
  # Concatenate the IV and encrypted data
  concatenated_data = iv + cipher_text

  # Compute the HMAC tag
  hmac_tag = hmac.HMAC(kh, hashes.SHA256(), backend=default_backend())
  hmac_tag.update(concatenated_data)
  hmac_result = hmac_tag.finalize()

  # Include the HMAC tag along with the encrypted data
  encrypted_data_with_hmac = iv + cipher_text + hmac_result
  
  return encrypted_data_with_hmac

#function to write metadata required for decryption
def write_metadata(cipher_suite, choice, salt, iteration_count, HMAC_key):
  file_path = os.getcwd()
  metadata_file_path = file_path+'\\metadata.json'
  metadata = {
        "Metadata": {
            "Encryption Algorithm": str(cipher_suite[choice][1]),
            "Hashing Algorithm in KDF": str(cipher_suite[choice][0]),
            "Iteration Count": int(iteration_count),
            "Salt": salt.hex(),
            "HMAC Key": HMAC_key.hex()
        }
    }
  with open(metadata_file_path, 'w') as metadata_file:
      json.dump(metadata, metadata_file, indent=4)
  
