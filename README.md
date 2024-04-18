# File-Encryption-Utility-using-CBC
This project utilizes the PBKDF2 (Password-Based Key Derivation Function 2) for key derivation and is compatible with various cipher suites, including combinations such as tripleDES with sha256, aes128 with sha256, and aes256 with sha512. The system supports both encryption and decryption functionalities, employing HMAC for securing the Initialization Vector (IV) and ciphertext. CBC chaining mode is used for the encryption and decryption. Developed entirely in Python, the utility offers a straightforward user interface using Tkinter for enhanced user interaction.

# Encryption script description – 
1.	The process involves four key functions: deriving the master key, deriving the encryption key from the master key, deriving the HMAC key from the master key, and performing the CBC block encryption.
2.	The derivation of the master key begins with the utilization of the PBKDF2 function. A random salt is generated, and the iteration count is fixed, determined based on optimal processing time. The key length is variable, depending on the cipher suite selected by the user.
3.	Subsequently, the encryption key is derived from the master key. The PBKDF2 function is again employed, with an iteration count set to 1 and a fixed salt used, tailored to the chosen cipher suite.
4.	Similarly, the HMAC key is derived from the master key, utilizing the PBKDF2 function with an iteration count set to 1 and a fixed salt corresponding to the selected cipher suite.
5.	The CBC block encryption process begins by creating an initialization vector (IV) sized according to the chosen algorithms within the cipher suite.
6.	A block size is then determined based on the cipher suite specifications.
7.	Padding is applied using the PKCS7 method, leveraging an inbuilt Python function. Subsequently, encryption is executed to produce the cipher text.
8.	An HMAC tag is generated using the IV and cipher text. Finally, the output data is written to a file, consisting of IV, cipher text, and HMAC tag.
9.	The metadata file is formatted as a JSON file, encompassing encryption and hashing algorithms, iteration count, salt, and the HMAC key.

# Decryption script description –
1.	The script encompasses four primary functions: deriving the master key using the user-provided password, deriving the decryption key, deriving the HMAC key using the master key, and performing decryption.
2.	To initiate the decryption process, the script initially retrieves metadata, obtaining values such as the initialization vector, iteration count used for master key derivation, and the cipher suite employed.
3.	Utilizing this metadata, the master key is derived, followed by the derivation of the decryption and HMAC keys.
4.	Subsequently, from the provided cipher text file, the script extracts the initialization vector, padded cipher text, and HMAC key.
5.	It computes the HMAC key using the metadata details and compares it with the HMAC key extracted from the cipher text file to verify integrity. If they match, it confirms that the file has not been tampered with and that the user-provided password was correct.
6.	In case of a mismatch, a message indicating HMAC validation failure is immediately displayed.
7.	Assuming successful HMAC validation, the script proceeds to decrypt the padded cipher text using the available keys and the CBC method.
8.	Upon decryption, the decrypted data is written to an output file in the same directory as the encrypted file, allowing the user to access it.

# UI script description – 
The UI features a straightforward design crafted with the tkinter library in Python, aimed at enhancing user interaction through intuitive buttons and file entry boxes. Comprising three scripts, the project's central script serves as the main hub, orchestrating the execution of the encryption and decryption functionalities.

•	Main Window: This window presents users with buttons to select their desired action—encryption or decryption.<br>
•	Encryption Window: Upon choosing encryption, a new window emerges, guiding users through file selection and password entry. Following encryption, a message window pops up to convey the outcome or any encountered errors.<br>
•	Decryption Window: Likewise, opting for decryption reveals a dedicated window where users input the file for decryption and its corresponding password. Subsequent to decryption, a message window promptly relays the result or any encountered errors.<br>

These message windows ensure transparent communication with users, providing timely feedback on the success or failure of encryption or decryption endeavors. Such a structured approach significantly improves user experience by seamlessly guiding users through each step while promptly addressing any potential issues.


