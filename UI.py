import tkinter as tk
from tkinter import filedialog, ttk
import Encryption
import Decryption
import time
import os
from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES, AES128, AES256
from tkinter import messagebox
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher

#function to choose a file using file explorer
def select_file(file_entry):
    file_path = tk.filedialog.askopenfilename()
    if file_path:
        file_entry.delete(0, tk.END)
        file_entry.insert(0, file_path)

#function to execute the ecryption process
def perform_encryption(file_path, password, cipher_suite, choice,encrypt_window):
    try:
        with open(file_path, 'rb') as file:
            file_content = file.read()
    except FileNotFoundError:
         messagebox.showinfo("Error", "File not found or path is incorrect.")
         return None, None, None

    '''Fixed iteration count and salt for the master key derivation
    The iteration count is determined based on the execution time taken to derive the master key.
    The code I used for finding that is as mentioned below
    start = time.time()
    # derive
    kdf = PBKDF2HMAC(
         algorithm=hashes.SHA256(),
         length=32,
         salt=salt,
         iterations=550136,
         backend=backend
     )
    key = kdf.derive(b"my great password")
    print("--- %s seconds ---" % (time.time() - start))

    Stats -
    count = 100000, time = 0.07872867584228516 seconds
    count = 1000000, time = 0.7721669673919678 seconds
    count = 550136, time = 0.4327545166015625 seconds

    I went with the mid value where the approximate time needed is 0.4 seconds.
    '''
    iteration_count = 550136
    salt = os.urandom(16)
    hashing_algo = cipher_suite[choice][0]
    
    if choice == 1:
        key_len = 24
    elif choice == 2:
        key_len = 16
    elif choice == 3:
        key_len = 32
    
    masterkey = Encryption.derive_master_key(hashing_algo, password, salt, iteration_count, key_len)
    ke = Encryption.derive_encryption_key(masterkey, cipher_suite, choice, key_len)
    kh = Encryption.derive_HMAC_key(masterkey, cipher_suite, choice, key_len)
    ciphertext, iv = Encryption.encrypt_with_algorithm(cipher_suite, choice, file_content, ke)
    encrypted_data_with_hmac = Encryption.last_step_encryption(kh, ciphertext, iv)
    metadata_json = Encryption.write_metadata(cipher_suite, choice, salt, iteration_count, kh)
    flag = output_file(file_path,encrypted_data_with_hmac,encrypt_window,metadata_json)
    
    
    return file_path, encrypted_data_with_hmac, cipher_suite[choice][0], kh, iv

#function that gets called when final "encrypt" button is clicked by user
def encryption_callback(file_entry, password_entry, choice_var, cipher_suite, encrypt_window):
    file_path = file_entry.get()
    password = password_entry.get()
    choice = choice_var.get()
    if choice:
        result = perform_encryption(file_path, password, cipher_suite, choice, encrypt_window)
        if result:
            pass
    else:
        messagebox.showerror("Error", "Please select a valid choice")

#Function that creates the output file which will have the encrypted data, this data will be HMAC covering the iv and cipher text.
def output_file(file_path,encrypted_data_with_hmac,encrypt_window,metadata_json):
    flag = 0
    directory, filename = os.path.split(file_path)
    output_file_path = os.path.join(directory, f"{filename}_enc")
    if output_file_path:
        with open(output_file_path, 'wb') as output_file:
            output_file.write(metadata_json.encode('utf-8'))
            output_file.write(b'\n')  
            output_file.write(encrypted_data_with_hmac) 

        window = tk.Toplevel(root)
        window.title("Update")
        
        message_label = tk.Label(window, text="File encrypted and saved.")
        message_label.pack(padx=10, pady=10)

        ok_button = tk.Button(window, text="Okay", command=lambda: close_application(window, encrypt_window))
        ok_button.pack(padx=10, pady=10)

#function that gets called when user selects the decrypt option
def decryption_callback():
    decrypt_window = tk.Toplevel(root)
    decrypt_window.title("Decryption")

    # File entry field for decryption
    file_entry = ttk.Entry(decrypt_window)
    file_entry.grid(row=0, column=1, padx=10, pady=10, sticky="ew")

    # File selection button for decryption
    file_button = ttk.Button(decrypt_window, text="Select File to Decrypt", command=select_file_decrypt(file_entry))
    file_button.grid(row=0, column=0, padx=10, pady=10)

    # Password entry field for decryption
    password_label = ttk.Label(decrypt_window, text="Enter Password:")
    password_label.grid(row=1, column=0, padx=10, pady=5)
    password_entry = ttk.Entry(decrypt_window, show="*")  
    password_entry.grid(row=1, column=1, padx=10, pady=5, sticky="ew")

    # Decrypt button
    decrypt_button = ttk.Button(decrypt_window, text="Decrypt", command=lambda: perform_decryption(decrypt_window))
    decrypt_button.grid(row=3, column=0, columnspan=2, padx=10, pady=10)

#function that performs decryption and is called when user clicks final "decrypt button.
def perform_decryption(file_entry, password_entry, decrypt_window):
    file_path = file_entry.get()
    password = password_entry.get()

    # Validate file path
    if not os.path.exists(file_path) or not file_path.endswith("_enc"):
        messagebox.showerror("Error", "Invalid or encrypted file not found.")
        return
        
    # Perform decryption
    metadata, encrypted_data_with_hmac = Decryption.read_metadata_from_json(file_path)
    salt = metadata["Salt"]
    iteration_count = metadata["Iteration Count"]
    hashing_algorithm = metadata["Hashing Algorithm in KDF"]
    encryption_algo = metadata["Encryption Algorithm"]
    provided_hmac = metadata["HMAC Key"]
    print(salt,hashing_algorithm)
    masterkey, key_len = Decryption.derive_masterkey(password, salt, iteration_count, hashing_algorithm, encryption_algo)
    kh = Decryption.derive_kh(masterkey, hashing_algorithm, key_len)
    ke = Decryption.derive_ke(masterkey, hashing_algorithm, key_len)
    iv, ciphertext = Decryption.decrypt_with_hmac(encrypted_data_with_hmac, encryption_algo, kh)

    if iv != False:
        flag = Decryption.decrypt_with_algorithm(encryption_algo, ciphertext, ke, iv, file_path)
    else:
        flag = False
        messagebox.showinfo("Failure", "File decryption failed, check password.")
        
    if flag == False:
        close_application(decrypt_window)
    else:
        messagebox.showinfo("Success", "File decrypted successfully.")
        close_application(decrypt_window)
        
# Function to select file for decryption
def select_file_decrypt(file_entry):
    file_path = filedialog.askopenfilename()
    if file_path:
        file_entry.delete(0, tk.END)
        file_entry.insert(0, file_path)


#opens a seperate window when user selects encrypt option from first window
def open_encrypt_window():
    cipher_suite = {1:['SHA256',TripleDES],2:['SHA256',AES128],3:['SHA512',AES256]}
    choice = 0
    encrypt_window = tk.Toplevel(root)
    encrypt_window.title("Encrypt File")
    
    # Create the file entry field
    file_entry = ttk.Entry(encrypt_window)

    # Define a lambda function to pass the file_entry widget to select_file
    select_file_command = lambda: select_file(file_entry)

    # Create the file selection button with the lambda function as command
    file_button = ttk.Button(encrypt_window, text="Upload File", command=select_file_command)
    file_button.grid(row=0, column=0, padx=10, pady=10)
    file_entry.grid(row=0, column=1, padx=10, pady=10, sticky="ew")

    # Password entry field (hidden)
    password_label = ttk.Label(encrypt_window, text="Enter Password:")
    password_label.grid(row=1, column=0, padx=10, pady=5)
    password_entry = ttk.Entry(encrypt_window, show="*")
    password_entry.grid(row=1, column=1, padx=10, pady=5, sticky="ew")

    # Cipher suite choices
    cipher_label = ttk.Label(encrypt_window, text="Choose Cipher Suite:")
    cipher_label.grid(row=2, column=0, padx=10, pady=5)
    choice_var = tk.IntVar()
    for choice, (hashing_algo, encryption_alg) in cipher_suite.items():
        ttk.Radiobutton(encrypt_window, text=f"{hashing_algo} with {encryption_alg.__name__}", variable=choice_var, value=choice).grid(row=choice+2, column=1, padx=10, pady=5, sticky="w")

    # Encryption button
    encrypt_button = ttk.Button(encrypt_window, text="Encrypt", command=lambda: encryption_callback(file_entry, password_entry, choice_var, cipher_suite, encrypt_window))
    encrypt_button.grid(row=len(cipher_suite) + 4, column=0, columnspan=2, padx=10, pady=10)

#opens a seperate window when user selects decrypt option in first window
def open_decrypt_window():
    decrypt_window = tk.Toplevel(root)
    decrypt_window.title("Decryption")

    # Define widgets for decryption window
    file_button = ttk.Button(decrypt_window, text="Select File to Decrypt", command=lambda: select_file_decrypt(file_entry))
    file_button.grid(row=0, column=0, padx=10, pady=10)
    
    # Create the file entry field
    file_entry = ttk.Entry(decrypt_window)
    file_entry.grid(row=0, column=1, padx=10, pady=10, sticky="ew")

    # Password entry field (hidden)
    password_label = ttk.Label(decrypt_window, text="Enter Password:")
    password_label.grid(row=1, column=0, padx=10, pady=5)
    password_entry = ttk.Entry(decrypt_window, show="*")  
    password_entry.grid(row=1, column=1, padx=10, pady=5, sticky="ew")

    decrypt_button = ttk.Button(decrypt_window, text="Decrypt", command=lambda: perform_decryption(file_entry, password_entry, decrypt_window))
    decrypt_button.grid(row=3, column=0, columnspan=2, padx=10, pady=10)

#function that can close any windows of tkinter when called
def close_application(*windows):
    for window in windows:
        window.destroy()

#main function
if __name__ == "__main__":
    start = time.time()
    root = tk.Tk()
    root.title("File Encryption Utility")

    encrypt_button = ttk.Button(root, text="Encrypt", command=open_encrypt_window)
    encrypt_button.pack(pady=10)

    decrypt_button = ttk.Button(root, text="Decrypt", command=open_decrypt_window)
    decrypt_button.pack(pady=10)

    root.mainloop()
    
    print("--- %s seconds ---" % (time.time() - start))
