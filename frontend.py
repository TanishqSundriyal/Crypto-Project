import customtkinter as ctk
from tkinter import filedialog, messagebox
import os

# Import cryptography libraries for AES-GCM and PBKDF2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# App Window Configuration
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

app = ctk.CTk()
app.title("🔒 Secure File Encryption & Decryption Tool")
app.geometry("720x500")

# ----- CRYPTO CONSTANTS (must match C++ values) -----
KEY_SIZE = 32         # 256 bits
SALT_SIZE = 16
PBKDF2_ITERATIONS = 100_000
GCM_IV_SIZE = 12
GCM_TAG_SIZE = 16

def derive_key(password, salt):
    """Derive AES-256 key from password and salt using PBKDF2-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file_compatible(input_path, output_path, password):
    """Encrypt file using AES-256-GCM and write [salt][iv][tag][ciphertext] to output_path."""
    # Read plaintext
    with open(input_path, 'rb') as f:
        plaintext = f.read()

    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt)
    iv = os.urandom(GCM_IV_SIZE)

    encryptor = Cipher(
        algorithms.AES(key), 
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag

    with open(output_path, 'wb') as f:
        f.write(salt)
        f.write(iv)
        f.write(tag)
        f.write(ciphertext)

def decrypt_file_compatible(input_path, output_path, password):
    """Decrypt a [salt][iv][tag][ciphertext] file using AES-256-GCM."""
    with open(input_path, 'rb') as f:
        raw = f.read()
    if len(raw) < SALT_SIZE + GCM_IV_SIZE + GCM_TAG_SIZE:
        raise ValueError("File too short or format error.")
    salt = raw[:SALT_SIZE]
    iv = raw[SALT_SIZE:SALT_SIZE+GCM_IV_SIZE]
    tag = raw[SALT_SIZE+GCM_IV_SIZE:SALT_SIZE+GCM_IV_SIZE+GCM_TAG_SIZE]
    ciphertext = raw[SALT_SIZE+GCM_IV_SIZE+GCM_TAG_SIZE:]

    key = derive_key(password, salt)
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()
    try:
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    except Exception as e:
        raise ValueError("Decryption failed: The password may be wrong or the file is corrupted.") from e

    with open(output_path, 'wb') as f:
        f.write(plaintext)

# ---- GUI LOGIC ----

def gui_encrypt_file():
    file_path = file_entry.get()
    password = password_entry.get()

    if not file_path or not os.path.exists(file_path):
        messagebox.showerror("Error", "Please select a valid file.")
        return
    if not password:
        messagebox.showerror("Error", "Please enter a password.")
        return
    if len(password) < 8:
        messagebox.showerror("Error", "Password must be at least 8 characters long.")
        return

    try:
        out_path = file_path + ".enc"
        encrypt_file_compatible(file_path, out_path, password)
        messagebox.showinfo("Success", f"✅ File encrypted successfully!\nSaved as {out_path}")
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed: {str(e)}")

def gui_decrypt_file():
    file_path = file_entry.get()
    password = password_entry.get()

    if not file_path or not os.path.exists(file_path):
        messagebox.showerror("Error", "Please select a valid encrypted file.")
        return
    if not password:
        messagebox.showerror("Error", "Please enter a password.")
        return

    try:
        # Properly remove .enc extension or append _decrypted
        if file_path.endswith(".enc"):
            out_path = file_path[:-4]
            if os.path.exists(out_path):
                base_name, ext = os.path.splitext(out_path)
                out_path = f"{base_name}_decrypted{ext}"
        else:
            base_name, ext = os.path.splitext(file_path)
            out_path = f"{base_name}_decrypted{ext}"

        decrypt_file_compatible(file_path, out_path, password)
        messagebox.showinfo("Success", f"✅ File decrypted successfully!\nSaved as {out_path}")
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {str(e)}")

def browse_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        file_entry.delete(0, ctk.END)
        file_entry.insert(0, file_path)

# ------------------- UI Layout -------------------

title = ctk.CTkLabel(app, text="🔒 Secure File Encryption & Decryption Tool", 
                     font=("Segoe UI", 24, "bold"), text_color="#00b4d8")
title.pack(pady=30)

frame = ctk.CTkFrame(app, corner_radius=15)
frame.pack(pady=20, padx=20, fill="x")

file_label = ctk.CTkLabel(frame, text="Select File:", font=("Segoe UI", 15))
file_label.grid(row=0, column=0, padx=20, pady=20, sticky="w")

file_entry = ctk.CTkEntry(frame, width=400, placeholder_text="Choose file to encrypt/decrypt...")
file_entry.grid(row=0, column=1, padx=10, pady=20)

browse_btn = ctk.CTkButton(frame, text="Browse", width=100, fg_color="#0077b6", hover_color="#023e8a", command=browse_file)
browse_btn.grid(row=0, column=2, padx=10, pady=20)

password_label = ctk.CTkLabel(frame, text="Enter Password:", font=("Segoe UI", 15))
password_label.grid(row=1, column=0, padx=20, pady=20, sticky="w")

password_entry = ctk.CTkEntry(frame, width=400, show="*", placeholder_text="Enter a strong password...")
password_entry.grid(row=1, column=1, padx=10, pady=20)

encrypt_btn = ctk.CTkButton(app, text="🔒 Encrypt File", width=220, height=40,
                            fg_color="#00b4d8", hover_color="#0077b6", command=gui_encrypt_file)
encrypt_btn.pack(pady=10)

decrypt_btn = ctk.CTkButton(app, text="🔓 Decrypt File", width=220, height=40,
                            fg_color="#ef233c", hover_color="#d90429", command=gui_decrypt_file)
decrypt_btn.pack(pady=10)

footer = ctk.CTkLabel(app, text="Developed by Srishti Bhatt | Cryptography Project",
                      font=("Segoe UI", 12), text_color="gray")
footer.pack(side="bottom", pady=15)

app.mainloop()
