import customtkinter as ctk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
import os, base64, hashlib

# App Window Configuration
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

app = ctk.CTk()
app.title("🔒 Secure File Encryption & Decryption Tool")
app.geometry("720x500")

# Generate encryption key using password
def generate_key(password):
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())

# Encrypt file function
def encrypt_file():
    file_path = file_entry.get()
    password = password_entry.get()

    if not file_path or not os.path.exists(file_path):
        messagebox.showerror("Error", "Please select a valid file.")
        return
    if not password:
        messagebox.showerror("Error", "Please enter a password.")
        return

    try:
        key = generate_key(password)
        fernet = Fernet(key)
        with open(file_path, "rb") as file:
            data = file.read()
        encrypted = fernet.encrypt(data)

        out_path = file_path + ".enc"
        with open(out_path, "wb") as enc_file:
            enc_file.write(encrypted)

        messagebox.showinfo("Success", f"✅ File encrypted successfully!\nSaved as {out_path}")
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed: {str(e)}")

# Decrypt file function
def decrypt_file():
    file_path = file_entry.get()
    password = password_entry.get()

    if not file_path or not os.path.exists(file_path):
        messagebox.showerror("Error", "Please select a valid encrypted file.")
        return
    if not password:
        messagebox.showerror("Error", "Please enter a password.")
        return

    try:
        key = generate_key(password)
        fernet = Fernet(key)
        with open(file_path, "rb") as enc_file:
            encrypted_data = enc_file.read()
        decrypted = fernet.decrypt(encrypted_data)

        # FIXED: Proper output file naming that preserves original extension
        if file_path.endswith(".enc"):
            # Remove .enc extension to get original filename
            out_path = file_path[:-4]
            # If file already exists, add "_decrypted" before extension
            if os.path.exists(out_path):
                base_name, ext = os.path.splitext(out_path)
                out_path = f"{base_name}_decrypted{ext}"
        else:
            # If file doesn't end with .enc, just add _decrypted
            base_name, ext = os.path.splitext(file_path)
            out_path = f"{base_name}_decrypted{ext}"
        
        with open(out_path, "wb") as dec_file:
            dec_file.write(decrypted)

        messagebox.showinfo("Success", f"✅ File decrypted successfully!\nSaved as {out_path}")
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {str(e)}")

# Browse file
def browse_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        file_entry.delete(0, ctk.END)
        file_entry.insert(0, file_path)

# -------------------- UI Layout --------------------

# Title Label
title = ctk.CTkLabel(app, text="🔒 Secure File Encryption & Decryption Tool", 
                     font=("Segoe UI", 24, "bold"), text_color="#00b4d8")
title.pack(pady=30)

# Frame for input fields
frame = ctk.CTkFrame(app, corner_radius=15)
frame.pack(pady=20, padx=20, fill="x")

# File Selection
file_label = ctk.CTkLabel(frame, text="Select File:", font=("Segoe UI", 15))
file_label.grid(row=0, column=0, padx=20, pady=20, sticky="w")

file_entry = ctk.CTkEntry(frame, width=400, placeholder_text="Choose file to encrypt/decrypt...")
file_entry.grid(row=0, column=1, padx=10, pady=20)

browse_btn = ctk.CTkButton(frame, text="Browse", width=100, fg_color="#0077b6", hover_color="#023e8a", command=browse_file)
browse_btn.grid(row=0, column=2, padx=10, pady=20)

# Password Input
password_label = ctk.CTkLabel(frame, text="Enter Password:", font=("Segoe UI", 15))
password_label.grid(row=1, column=0, padx=20, pady=20, sticky="w")

password_entry = ctk.CTkEntry(frame, width=400, show="*", placeholder_text="Enter a strong password...")
password_entry.grid(row=1, column=1, padx=10, pady=20)

# Buttons
encrypt_btn = ctk.CTkButton(app, text="🔒 Encrypt File", width=220, height=40,
                            fg_color="#00b4d8", hover_color="#0077b6", command=encrypt_file)
encrypt_btn.pack(pady=10)

decrypt_btn = ctk.CTkButton(app, text="🔓 Decrypt File", width=220, height=40,
                            fg_color="#ef233c", hover_color="#d90429", command=decrypt_file)
decrypt_btn.pack(pady=10)

# Footer
footer = ctk.CTkLabel(app, text="Developed by Srishti Bhatt | Cryptography Project",
                      font=("Segoe UI", 12), text_color="gray")
footer.pack(side="bottom", pady=15)

# Run the app
app.mainloop()
