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