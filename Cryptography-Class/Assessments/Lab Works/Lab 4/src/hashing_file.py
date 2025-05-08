import hashlib

def compute_file_hash(filepath):
    """Compute SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):  # Read file in chunks
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()

# Example usage
file1 = r"C:\Users\fl4me\Documents\Cryptography\Raja-Haiqal\Cryptography-Class\Assessments\Lab Works\Lab 4\src\file1.txt"
file2 = r"C:\Users\fl4me\Documents\Cryptography\Raja-Haiqal\Cryptography-Class\Assessments\Lab Works\Lab 4\src\file2.txt"

hash1 = compute_file_hash(file1)
hash2 = compute_file_hash(file2)

print(f"Hash of {file1}:", hash1)
print(f"Hash of {file2}:", hash2)
