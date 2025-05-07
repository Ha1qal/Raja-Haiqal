
# Lab 4: Implementing Cryptography with Python

**Name:** Adli Jaafar  
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

You can see Danish encrypt python code in his github repo()

I will be using this python code that i have created to decrypt Danish's message with the key and iv given.
```python
from Crypto.Cipher import AES
import base64

# 1. Paste your values here (from your encryption output)
key = base64.b64decode("tvPrWH2wVHEtBv4NmHNAoyrTKIdHcVGj5clf2V8TE8g=")
iv = base64.b64decode("PUgXpZIefjVR7BuwzsiSCg==")
ciphertext = base64.b64decode("l/+waUOVxpN0OqS5Mibim5mRmqb1Ez0zwsV2cmeZatOP2eYF2cQxMPG4By7LXBjU")

# 2. Create cipher for decryption
cipher = AES.new(key, AES.MODE_CBC, iv)

# 3. Decrypt ciphertext
padded_plaintext = cipher.decrypt(ciphertext)

# 4. Remove padding
pad_len = padded_plaintext[-1]
plaintext = padded_plaintext[:-pad_len]

print("Decrypted:", plaintext.decode())
```
the output:
![aes decryption](image.png)

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

I will be creating private and public key and give public key to danish for him to encrypt the message
```python
from Crypto.PublicKey import RSA

# 1. Generate RSA key pair (2048 bits is standard)
key_pair = RSA.generate(2048)

# 2. Export the private key (keep this secret!)
private_key = key_pair.export_key()
with open("raja_private.pem", "wb") as f:
    f.write(private_key)

# 3. Export the public key (share this with you for encryption)
public_key = key_pair.publickey().export_key()
with open("raja_public.pem", "wb") as f:
    f.write(public_key)

print("RSA key pair generated.")
```
the output will give 2 file and that is raja_public.pem and raja_private.pem.I will give danish my raja_public.pem

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
import hashlib

# Input data
data1 = "hello"
data2 = "hello world"

# Hash
hash1 = hashlib.sha256(data1.encode()).hexdigest()
hash2 = hashlib.sha256(data2.encode()).hexdigest()

print("Hash of data1:", hash1)
print("Hash of data2:", hash2)
```

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

```python
# <paste here>
```

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

## ✅ D. Bonus Tips

- Always store your private keys securely. Never hard-code them in public scripts.
- Use libraries like `cryptography`, `pycryptodome`, or `hashlib` for reliable implementations.
- For production systems, avoid ECB mode and use secure key management solutions.
