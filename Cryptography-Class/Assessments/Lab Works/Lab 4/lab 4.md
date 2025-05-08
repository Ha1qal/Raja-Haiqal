
# Lab 4: Implementing Cryptography with Python

**Name:** Raja Muhammad Haiqal Shah Bin Raja Muzairil Shah  
**Partner Name:** Ahmad Danish Haikal Bin Abdullah  
**Course:** Network Security  
**Lab Date:** April 20  
**Lab Type:** Hands-On + Report + Demo/Debrief  
**Total Marks:** 15  

---

## 🧠 A. Objective

This lab introduces four fundamental cryptographic techniques and how they are implemented in Python. The objectives are:

1. Implementing symmetric encryption using AES for confidentiality.
2. Using RSA for secure asymmetric encryption and digital signatures.
3. Applying SHA-256 hashing to ensure data integrity.
4. Demonstrating digital signing and signature verification for authenticity and non-repudiation.

Each task aims to simulate real-world security practices such as secure file transfer, password protection, and message authenticity verification.

---

## 🧪 B. Lab Tasks

### 🔐 Task 1: Symmetric Encryption (AES)

#### ✅ Objective
To encrypt and decrypt a plaintext message using AES (Advanced Encryption Standard), a symmetric key algorithm that is fast and secure for encrypting data.

#### 🔧 Implementation

You can see how Danish encrypt using aes-cbc in python code in his [github repo](https://github.com/nishsem/Danish/blob/main/Cryptography-Class/Assessments/2-Lab-Works-20%25/Lab-Work-4/readme.md#task-1-symmetric-encryption-aes)

I will be using this python code that i have created to decrypt Danish's message with the key and iv given.
```python
from Crypto.Cipher import AES  # NOTE: Import AES cipher from pycryptodome
import base64  # NOTE: Import base64 to decode the encoded key, IV, and ciphertext

# 1. Paste your values here (from your encryption output)
# NOTE: Decode the base64-encoded AES key
key = base64.b64decode("tvPrWH2wVHEtBv4NmHNAoyrTKIdHcVGj5clf2V8TE8g=")

# NOTE: Decode the base64-encoded Initialization Vector (IV)
iv = base64.b64decode("PUgXpZIefjVR7BuwzsiSCg==")

# NOTE: Decode the base64-encoded ciphertext
ciphertext = base64.b64decode("l/+waUOVxpN0OqS5Mibim5mRmqb1Ez0zwsV2cmeZatOP2eYF2cQxMPG4By7LXBjU")

# 2. Create cipher for decryption
# NOTE: Create AES cipher object in CBC mode using the key and IV
cipher = AES.new(key, AES.MODE_CBC, iv)

# 3. Decrypt ciphertext
# NOTE: Decrypt the ciphertext to get padded plaintext
padded_plaintext = cipher.decrypt(ciphertext)

# 4. Remove padding
# NOTE: Get the value of the last byte to know how many padding bytes to remove
pad_len = padded_plaintext[-1]

# NOTE: Slice off the padding to get the original plaintext
plaintext = padded_plaintext[:-pad_len]

# NOTE: Decode bytes to string and print the result
print("Decrypted:", plaintext.decode())
```
the output:

![aes decrypt result](screenshots/aes_decryption_result.png)

#### 📚 Explanation

- **AES Basics:** AES is a block cipher with a fixed block size of 128 bits and key sizes of 128, 192, or 256 bits.
- **Mode of Operation:** ECB (Electronic Codebook) or CBC (Cipher Block Chaining) modes are commonly used. ECB is simpler but less secure because it reveals patterns.
- **Padding:** Since AES requires fixed-size input, padding is used to ensure the message fits the required block size.
- **Security Note:** ECB mode is not recommended in production due to its pattern leakage vulnerability. CBC or GCM is preferred for security.

---

### 🔑 Task 2: Asymmetric Encryption (RSA)

#### ✅ Objective
To implement RSA, an asymmetric algorithm, for encrypting a message using a public key and decrypting it with the private key.

#### 🔧 Implementation

I will be creating private and public key and give public key to danish for him to encrypt the message.
```python
from Crypto.PublicKey import RSA  # Import the RSA module from PyCryptodome for generating RSA keys

# 1. Generate RSA key pair (2048 bits is standard for secure encryption)
key_pair = RSA.generate(2048)  # Create a new RSA key pair with 2048-bit key size

# 2. Export the private key (keep this secret!)
private_key = key_pair.export_key()  # Convert the private key to a byte format suitable for saving
with open("raja_private.pem", "wb") as f:  # Open a file in write-binary mode to store the private key
    f.write(private_key)  # Save the private key to the file "raja_private.pem"

# 3. Export the public key (share this with others for encryption)
public_key = key_pair.publickey().export_key()  # Extract the public key from the key pair and convert to bytes
with open("raja_public.pem", "wb") as f:  # Open a file in write-binary mode to store the public key
    f.write(public_key)  # Save the public key to the file "raja_public.pem"

print("RSA key pair generated.")  # Inform the user that the key pair has been successfully created
```
the output will give 2 file and that is raja_public.pem and raja_private.pem.I will give danish my raja_public.pem.

See Danish's [Github repo](https://github.com/nishsem/Danish/blob/main/Cryptography-Class/Assessments/2-Lab-Works-20%25/Lab-Work-4/readme.md#task-2-asymmetric-encryption-rsa) to see how he encrypt using my public key()

then i try to decrypt the message given by Danish using my private key.
```python
from Crypto.PublicKey import RSA  # Import the RSA module to handle RSA keys
from Crypto.Cipher import PKCS1_OAEP  # Import the cipher method for RSA decryption
import base64  # Import base64 to decode the encoded ciphertext

# 1. Load private key
# NOTE: The RSA private key is stored as a multi-line string in PEM format
private_key_str = '''-----BEGIN RSA PRIVATE KEY-----
... (my private key content here) ...
-----END RSA PRIVATE KEY-----'''

# NOTE: Import the RSA key object from the PEM-formatted string
private_key = RSA.import_key(private_key_str)

# 2. Decode ciphertext
# NOTE: The ciphertext is base64-encoded, so decode it back to raw bytes
ciphertext = base64.b64decode("ScA1VOwk5IhOOxCcNwVV...")  # Truncated for readability

# 3. Decrypt
# NOTE: Initialize the RSA cipher using OAEP padding and the imported private key
cipher_rsa = PKCS1_OAEP.new(private_key)

# NOTE: Decrypt the ciphertext to retrieve the original plaintext message
plaintext = cipher_rsa.decrypt(ciphertext)

# NOTE: Print the decrypted message, converting bytes to a string
print("Decrypted:", plaintext.decode())
```
the output:

![rsa decryption](screenshots/rsa_decryption.png)

#### 📚 Explanation

- **Key Pair Generation:** RSA involves two mathematically linked keys – one public (for encryption) and one private (for decryption).
- **Use Case:** Ideal for transmitting a secret key or short confidential messages over an insecure network.
- **Padding Scheme:** OAEP (Optimal Asymmetric Encryption Padding) is used to make RSA encryption more secure.
- **Security Note:** RSA is slower than AES and usually used to encrypt small data (like a symmetric key), not full messages.

---

### 🔍 Task 3: Hashing (SHA-256)

#### ✅ Objective
To compute the SHA-256 hash of different messages to observe how small changes in input produce significantly different hashes (avalanche effect).

#### 🔧 Implementation

```python
import hashlib  # Importing the hashlib module to perform hashing (e.g., SHA-256)

# Input data
data1 = "hello"     # First input string (no space at the end)
data2 = "hello "    # Second input string (with a space at the end)

# Hash
# Compute the SHA-256 hash of the first input string after encoding it to bytes
hash1 = hashlib.sha256(data1.encode()).hexdigest()

# Compute the SHA-256 hash of the second input string after encoding it to bytes
hash2 = hashlib.sha256(data2.encode()).hexdigest()

# Print the resulting hashes
# This shows how even a small change (like a space) completely changes the hash
print("Hash of data1:", hash1)
print("Hash of data2:", hash2)
```
the output:

![hash output](screenshots/hash_output.png)

see even i added just a " "(space) after the word "Hello" it changed dastically.
See Danish's output too in his [Github Repo](https://github.com/nishsem/Danish/blob/main/Cryptography-Class/Assessments/2-Lab-Works-20%25/Lab-Work-4/readme.md#task-3-hashing-sha-256)

Same goes as hashing a file:
```python
import hashlib  # Import Python's built-in library for cryptographic hashing functions

def compute_file_hash(filepath):
    """
    Compute SHA-256 hash of a file.
    This function takes the path of a file and returns its SHA-256 hash in hexadecimal.
    """
    sha256_hash = hashlib.sha256()  # Create a new SHA-256 hash object

    # Open the file in binary mode ('rb') to read bytes
    with open(filepath, "rb") as f:
        # Read the file in chunks of 4096 bytes to handle large files efficiently
        for chunk in iter(lambda: f.read(4096), b""):  
            sha256_hash.update(chunk)  # Update the hash with the content of each chunk

    return sha256_hash.hexdigest()  # Return the final hash value in hexadecimal format

# Example usage — specify the full path to each file
file1 = r"C:\Users\fl4me\Documents\Cryptography\Raja-Haiqal\Cryptography-Class\Assessments\Lab Works\Lab 4\src\file1.txt"
file2 = r"C:\Users\fl4me\Documents\Cryptography\Raja-Haiqal\Cryptography-Class\Assessments\Lab Works\Lab 4\src\file2.txt"

# Compute the hash for both files
hash1 = compute_file_hash(file1)
hash2 = compute_file_hash(file2)

# Print the SHA-256 hash of each file
print(f"Hash of {file1}:", hash1)
print(f"Hash of {file2}:", hash2)

```
output if i added " "(space) for the second text file:

![hashing with space](screenshots/hashingfilespace.png)

the output is completely different.

what if we have 2 file with same content?:

![hashing same input both file](screenshots/hashingsamefile.png)

the hash would be the same because the content are the same!

#### 📚 Explanation

- **SHA-256 Overview:** A member of the SHA-2 family, it produces a 256-bit (64-character) hexadecimal hash.
- **Deterministic Output:** The same input always produces the same output.
- **One-Way Function:** It's computationally infeasible to reverse or find collisions (two inputs that produce the same hash).
- **Application:** Used in digital signatures, blockchain, file integrity checks, and password storage.

---

### ✍️ Task 4: Digital Signatures (RSA)

#### ✅ Objective
To demonstrate how RSA can be used not only for encryption but also for signing a message, ensuring its integrity and authenticity.

#### 🔧 Implementation

First I create a file to sign(digital_file.txt) and a signature file using my private key.
```python
from Crypto.Signature import pkcs1_15  # Importing PKCS#1 v1.5 standard for creating RSA signatures
from Crypto.PublicKey import RSA       # Module for handling RSA key import/export
from Crypto.Hash import SHA256         # SHA256 is used to hash the message (file content)
import base64                          # Base64 used to encode signature for easier saving/sharing

# 1. Load your private key (used to generate digital signature)
private_key_str = '''-----BEGIN RSA PRIVATE KEY-----
... (my private key content here) ...
-----END RSA PRIVATE KEY-----'''  # The actual private key content must be inserted here

private_key = RSA.import_key(private_key_str)  # Converts the PEM-format string to an RSA key object

# 2. Load the file you want to digitally sign
filename = r"C:\Users\fl4me\Documents\Cryptography\Raja-Haiqal\Cryptography-Class\Assessments\Lab Works\Lab 4\src\digital_file.txt"
with open(filename, "rb") as f:  # Open the file in binary mode for reading
    file_data = f.read()  # Read the entire file content

# 3. Create a hash (SHA-256) of the file data
hash = SHA256.new(file_data)  # Compute the SHA-256 hash of the file. This hash will be signed.

# 4. Create a digital signature of the hash using your private key
signature = pkcs1_15.new(private_key).sign(hash)  # Sign the hash using the private key

# 5. Save the digital signature to a file (encoded in Base64)
signature_b64 = base64.b64encode(signature).decode('utf-8')  # Convert the binary signature to Base64 for easy storage
with open("file_signature.txt", "w") as sig_file:  # Create/open a text file to save the signature
    sig_file.write(signature_b64)  # Write the Base64 signature to the file

print(f"Signature saved to 'file_signature.txt'.")  # Let the user know the signature was created and saved
```
then i created the signature file.After that,I need to give the signature file and the text file that I signed(digital_file.txt) to danish to verify.[Danish' Github repo](https://github.com/nishsem/Danish/blob/main/Cryptography-Class/Assessments/2-Lab-Works-20%25/Lab-Work-4/readme.md#task-4-digital-signatures-rsa)


#### 📚 Explanation

- **Digital Signature Process:**
  1. Hash the message using SHA-256.
  2. Sign the hash with the private RSA key.
  3. Verify the signature using the public RSA key.
- **Purpose:** Prevent tampering and impersonation. If the message or signature is altered, verification fails.
- **Security Benefit:** Non-repudiation — the sender cannot deny authorship of the signed message.
- **Real-World Use:** Email signing (S/MIME), software distribution, digital certificates (SSL/TLS).

---


## 🧠 C. Conclusion

This lab successfully demonstrated the use of Python libraries to implement cryptographic functions:

- **AES** for fast, efficient symmetric encryption.
- **RSA** for secure key exchange and digital signatures.
- **SHA-256** to generate tamper-evident hash values.
- **Digital signatures** for authenticity and non-repudiation.

These implementations are fundamental in real-world cybersecurity solutions such as encrypted messaging, secure email, HTTPS, and blockchain. Mastery of these tools and concepts is essential for any cybersecurity professional.

---

