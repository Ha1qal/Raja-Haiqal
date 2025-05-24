from Crypto.Cipher import AES
from hashlib import sha256
import os

# Derive the same key as the ransomware
KEY_SUFFIX = "RahsiaLagi"
KEY_STR = f"Bukan{KEY_SUFFIX}"
KEY = sha256(KEY_STR.encode()).digest()[:16]

def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

def decrypt_file(filepath):
    with open(filepath, "rb") as f:
        ciphertext = f.read()
    cipher = AES.new(KEY, AES.MODE_ECB)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext)
    output_path = filepath.replace(".enc", "_decrypted.txt")
    with open(output_path, "wb") as f:
        f.write(plaintext)
    print(f"Decrypted: {filepath} -> {output_path}")

def main():
    folder = "."
    for file in os.listdir(folder):
        if file.endswith(".enc"):
            decrypt_file(os.path.join(folder, file))

if __name__ == "__main__":
    main()