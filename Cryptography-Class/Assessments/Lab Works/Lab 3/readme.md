
# Lab 3: Hands-on Exploration of Cryptographic Tools: Hashing, Encryption, and Digital Signatures

## 👨‍💻 Author: Raja Muhammad Haiqal Shah  
**Date:** April 20, 2025  
**Lab Instructor:** Adli Jaafar

---

## 🔍 Overview

This lab introduces OpenSSL and related tools for fundamental cryptographic operations:  
- Symmetric Encryption (AES-256-CBC)  
- Asymmetric Encryption (RSA)  
- Hashing (SHA-256)  
- Digital Signatures (RSA + SHA-256)  

---

## 🔧 Task 1: Symmetric Encryption and Decryption using AES-256-CBC

### Tools Used
- `OpenSSL`

### Commands Executed

```bash
# Step 1: Generate a 256-bit (32-byte) random key
openssl rand -hex 32 > aes.key

# Step 2: Save a message
echo "Confidential message from Labu to Labi." > haiqal.txt

# Step 3: Encrypt the file using AES-256-CBC
openssl enc -aes-256-cbc -salt -in haiqal.txt -out haiqal.enc -pass file:./aes.key

# Step 4: Decrypt the file using the same key
openssl enc -d -aes-256-cbc -in haiqal.enc -out haiqal_decrypted.txt -pass file:./aes.key

# Step 5: Compare original and decrypted
diff haiqal.txt haiqal_decrypted.txt
```

### Analysis of Results
The `diff` command returns no output, indicating both files are identical. This demonstrates successful symmetric encryption and decryption using AES-256-CBC.

---

## 🔐 Task 2: Asymmetric Encryption and Decryption using RSA

### Tools Used
- `OpenSSL`

### Commands Executed

```bash
# Step 1: Generate RSA private key (2048-bit)
openssl genpkey -algorithm RSA -out labi_private.pem -pkeyopt rsa_keygen_bits:2048

# Step 2: Extract public key
openssl rsa -pubout -in labi_private.pem -out labi_public.pem

# Step 3: Create secret message
echo "RAHSIA: Labi must not leak this." > rahsia.txt

# Step 4: Encrypt using public key
openssl rsautl -encrypt -inkey labi_public.pem -pubin -in rahsia.txt -out rahsia.enc

# Step 5: Decrypt using private key
openssl rsautl -decrypt -inkey labi_private.pem -in rahsia.enc -out rahsia_decrypted.txt

# Step 6: Compare files
diff rahsia.txt rahsia_decrypted.txt
```

### Analysis of Results
Decrypted file matched original. RSA encryption using public key and decryption using private key ensures secure transmission. Minimum 2048-bit key ensures modern cryptographic strength.

---

## 🧮 Task 3: Hashing and Message Integrity using SHA-256

### Tools Used
- `OpenSSL`
- `sha256sum` (for comparison)

### Commands Executed

```bash
# Step 1: Create file
echo "This is a hash test message." > haiqal.txt

# Step 2: Generate SHA-256 hash
openssl dgst -sha256 haiqal.txt

# Step 3: Modify file slightly
echo " " >> haiqal.txt

# Step 4: Generate new hash
openssl dgst -sha256 haiqal.txt
```

### Analysis of Results
Even a minor change produced a completely different hash. This demonstrates hash functions' sensitivity to input and supports integrity verification.

---

## ✍️ Task 4: Digital Signatures using RSA

### Tools Used
- `OpenSSL`

### Commands Executed

```bash
# Step 1: Create document
echo "This is the signed agreement." > agreement.txt

# Step 2: Sign with RSA private key (SHA-256)
openssl dgst -sha256 -sign labi_private.pem -out agreement.sig agreement.txt

# Step 3: Verify signature with public key
openssl dgst -sha256 -verify labi_public.pem -signature agreement.sig agreement.txt

# Step 4: Modify file and test verification
echo "Altered." >> agreement.txt
openssl dgst -sha256 -verify labi_public.pem -signature agreement.sig agreement.txt
```

### Analysis of Results
Signature verification failed after modifying the file, proving that digital signatures preserve both authenticity and integrity.

---

## 🛠️ Problems Encountered and Solutions

| Problem | Solution |
|--------|----------|
| Misused key file path | Used `-pass file:./aes.key` to fix |
| RSA encryption failed | Used `rsautl` with `-pubin` option |
| Signature verification failed unexpectedly | Double-checked file and signature pair, fixed by using correct unmodified file |

**Resources Used:** `man openssl`, OpenSSL documentation, Stack Overflow

---

## ✅ Conclusion

This lab successfully demonstrated key cryptographic operations using OpenSSL. It showed how encryption ensures confidentiality, hashing ensures integrity, and digital signatures ensure both authenticity and integrity. Each command taught valuable insights into cryptographic practices.

