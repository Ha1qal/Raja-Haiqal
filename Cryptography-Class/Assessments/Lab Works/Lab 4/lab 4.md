
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
the output will give 2 file and that is raja_public.pem and raja_private.pem.I will give danish my raja_public.pem.

See Danish's Github repo to see how he encrypt using my public key()

then i try to decrypt the message given by Danish using my private key.
```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

# 1. Load private key
private_key_str = '''-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1JqRbGfSKHggm4rllcd7WnsCa4Pm7y4/4xw01+pNI3gtWXOv
LX3xU3E9CdQzU8U7rFG3e8on4D7CleQdDclWam92Qn4wcC16oWqwhwrWP3+krvYj
KEFx7pMMvvg/Jc/shnyjugNogyN7guhtMsdfUDOsxOsk4GN/1iW0oOfrNnm7DrhW
Ma6yL9lKIjnLr96jZOUSRl7+tld5nRwvsDmLcgl5oGM+KMWi6hcsn/lvzGz+i53j
74oaI9uAMRtfd5bvaRg6vjUQQun9gp1CdJ0ho3+qWDWZqcE0ew7xCpO40sbVwY2B
3Y7XAFAp81vPLFalnGVBa70SP7tMVvRDRimJ0wIDAQABAoIBAGnXxbxVd5AENh+Z
p7DIjgW+pbbHBQpgWRgE693uXJbi9pjI+hZI1AL5piylgyQaVhn02Mb9HpsKQ6+B
0GETsjzs3tA9qHnAeoOv7NBeOcmFD4S3L0uUQVdHyBmu1ylI+XT+yjgKCFb5LD1A
31RfY3k3MLUcZ9B6WKNRRDqzGyuTyALgCUbBJVHYHS959mtW7A4Bm924xP96SrZI
10cxQfadw9TT08B7drKf0qNdV5DVNJ+PDwNfMzH488+8PLCWF1WmUMsNTjfttuyG
N/itX6Ewusq69PaZJBPuoTi++1kBMhM69aJ+yaVWr4RLkpBRl+vKTfKnAT5RMPiQ
RFaiQkkCgYEA2RduAWLaepQE/GtE7EJYfAHnKYFPjqWm/44MwY/QmgcYMCzGe6+C
8l3vMr7klhIkmSyw1e8zKHtf/5luvYWv0vyeC42XpJwA7mLcXBmdCmoMARblF5g7
XdVWvk+gmWM2nrO8QrallPIs8OUSpsYOnrrpBYHGGezdLeToX368T+UCgYEA+rU7
eCIpKwoAzKugGD+CyOMJofBf4Tzcjjwh+W3LHT958xlN9oP4Dfjkt0NTHHNuzsWA
r3tcCCDj1/aLChb6Y9GkUrkFe74qz9mTTySjhKLZCvgISR+vOuP/Ytcx1FLZf57m
/2HBO67dnKoMj+6L0RNy0hF0kOJHOaaBMzMcp1cCgYA+5CTATg0ROdR/8+uRrl7H
/h0jzwxnPOI2YsabRLigBrIhMreFmYEMCd6ECv1Z5IOpxGKud4+QiL105NRKH3Ki
YwC+RBTMYU17wjQoklsGa1Zy8lkIDtgUBPwOQi86gJ2QOG2vvg4WKlqOpy5SFkqh
/XAIYmIrnI0vAIO5NpQDaQKBgQCD3uAxCIbvBIv3HC9RkdaRJBrk+zLznrfEeQzF
zmKQN9tFa4H+sNvBPbHQU7FbvbwDNw/BPfnirKor5pqr6/o4lwUAHiIsPJL4UVGS
x4rbMW1Iv75b+DaLm3Gx489qB0owPrzyh9DEO+6FgUyqSKdyifBTXqsZqmwcfuBm
tfPUcQKBgQCGpCEPCBf6Xv0Mn3wXZRYWKgTlRC3ChqsqOO8x3zPgOZGWm3x5byO3
H81hQMANM1t0ZAzh3/Aoz0gk0H/0zjWWDlr9FpRrBkymWQe5CtWLXO5IDV+RgVfq
g5JSVKkQHGYgGOu7VgzPyFTPy+G/6z/JR7ftmvxvIqjPa4OesHbAng==
-----END RSA PRIVATE KEY-----'''

private_key = RSA.import_key(private_key_str)

# 2. Decode ciphertext
ciphertext = base64.b64decode("ScA1VOwk5IhOOxCcNwVVM2HJDO2ni6oxAI8lyVXndS5bJSppDKUuQ+fwTVSQQbsaHTJXrXEnStV7EVK/cn1HqGCEmkg+aUZ3I+FY97upXRAaG92Lvh8Zgfy2HN4gZofbcrGvdMlniGAUszP5M2wcjtO4e2IbswKNTf0uaJrUIqZn3eNMFSqArrMAo4eIoAoJ3f61jIkeUTJB8sJHvzVXkVgcjFY7zLlU+sg3Q0FAqm8Ipi6nKQbyx3JPWMub/aZtZpZER11ThEQfw8+xFKBvaiLlG258VajrCReT8dgseYCeDeCpN3JG90uXP35K0aQ6P+sJysjO1UZTDx0cTYp4NA==")

# 3. Decrypt
cipher_rsa = PKCS1_OAEP.new(private_key)
plaintext = cipher_rsa.decrypt(ciphertext)

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

First I create a file to sign(digital_file.txt) and a signature file using my private key.
```python
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
import base64

# 1. Load Raja's private key from the string (PEM format)
private_key_str = '''-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1JqRbGfSKHggm4rllcd7WnsCa4Pm7y4/4xw01+pNI3gtWXOv
LX3xU3E9CdQzU8U7rFG3e8on4D7CleQdDclWam92Qn4wcC16oWqwhwrWP3+krvYj
KEFx7pMMvvg/Jc/shnyjugNogyN7guhtMsdfUDOsxOsk4GN/1iW0oOfrNnm7DrhW
Ma6yL9lKIjnLr96jZOUSRl7+tld5nRwvsDmLcgl5oGM+KMWi6hcsn/lvzGz+i53j
74oaI9uAMRtfd5bvaRg6vjUQQun9gp1CdJ0ho3+qWDWZqcE0ew7xCpO40sbVwY2B
3Y7XAFAp81vPLFalnGVBa70SP7tMVvRDRimJ0wIDAQABAoIBAGnXxbxVd5AENh+Z
p7DIjgW+pbbHBQpgWRgE693uXJbi9pjI+hZI1AL5piylgyQaVhn02Mb9HpsKQ6+B
0GETsjzs3tA9qHnAeoOv7NBeOcmFD4S3L0uUQVdHyBmu1ylI+XT+yjgKCFb5LD1A
31RfY3k3MLUcZ9B6WKNRRDqzGyuTyALgCUbBJVHYHS959mtW7A4Bm924xP96SrZI
10cxQfadw9TT08B7drKf0qNdV5DVNJ+PDwNfMzH488+8PLCWF1WmUMsNTjfttuyG
N/itX6Ewusq69PaZJBPuoTi++1kBMhM69aJ+yaVWr4RLkpBRl+vKTfKnAT5RMPiQ
RFaiQkkCgYEA2RduAWLaepQE/GtE7EJYfAHnKYFPjqWm/44MwY/QmgcYMCzGe6+C
8l3vMr7klhIkmSyw1e8zKHtf/5luvYWv0vyeC42XpJwA7mLcXBmdCmoMARblF5g7
XdVWvk+gmWM2nrO8QrallPIs8OUSpsYOnrrpBYHGGezdLeToX368T+UCgYEA+rU7
eCIpKwoAzKugGD+CyOMJofBf4Tzcjjwh+W3LHT958xlN9oP4Dfjkt0NTHHNuzsWA
r3tcCCDj1/aLChb6Y9GkUrkFe74qz9mTTySjhKLZCvgISR+vOuP/Ytcx1FLZf57m
/2HBO67dnKoMj+6L0RNy0hF0kOJHOaaBMzMcp1cCgYA+5CTATg0ROdR/8+uRrl7H
/h0jzwxnPOI2YsabRLigBrIhMreFmYEMCd6ECv1Z5IOpxGKud4+QiL105NRKH3Ki
YwC+RBTMYU17wjQoklsGa1Zy8lkIDtgUBPwOQi86gJ2QOG2vvg4WKlqOpy5SFkqh
/XAIYmIrnI0vAIO5NpQDaQKBgQCD3uAxCIbvBIv3HC9RkdaRJBrk+zLznrfEeQzF
zmKQN9tFa4H+sNvBPbHQU7FbvbwDNw/BPfnirKor5pqr6/o4lwUAHiIsPJL4UVGS
x4rbMW1Iv75b+DaLm3Gx489qB0owPrzyh9DEO+6FgUyqSKdyifBTXqsZqmwcfuBm
tfPUcQKBgQCGpCEPCBf6Xv0Mn3wXZRYWKgTlRC3ChqsqOO8x3zPgOZGWm3x5byO3
H81hQMANM1t0ZAzh3/Aoz0gk0H/0zjWWDlr9FpRrBkymWQe5CtWLXO5IDV+RgVfq
g5JSVKkQHGYgGOu7VgzPyFTPy+G/6z/JR7ftmvxvIqjPa4OesHbAng==
-----END RSA PRIVATE KEY-----'''

private_key = RSA.import_key(private_key_str)

# 2. Load the message from the txt file
filename = r"C:\Users\fl4me\Documents\Cryptography\Raja-Haiqal\Cryptography-Class\Assessments\Lab Works\Lab 4\src\digital_file.txt"  # Raja will sign this file
with open(filename, "rb") as f:
    file_data = f.read()

# 3. Create a hash of the file data
hash = SHA256.new(file_data)

# 4. Sign the hash using Raja's private key
signature = pkcs1_15.new(private_key).sign(hash)

# 5. Save the signature to a file
signature_b64 = base64.b64encode(signature).decode('utf-8')
with open("file_signature.txt", "w") as sig_file:
    sig_file.write(signature_b64)

print(f"Signature saved to 'file_signature.txt'.")
```
then i created the signature file.After that,I need to give the signature file and the text file that I signed(digital_file.txt) to danish to verify.
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
