import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
import os

# ================== Generate or load key ==================
def load_key():
    if not os.path.exists("secret.key"):
        key = Fernet.generate_key()
        with open("secret.key", "wb") as key_file:
            key_file.write(key)
    else:
        with open("secret.key", "rb") as key_file:
            key = key_file.read()
    return key

fernet = Fernet(load_key())

# ================== Functions ==================
def encrypt_text():
    text = input_text.get("1.0", tk.END).strip()
    if not text:
        messagebox.showwarning("Warning", "Enter some text to encrypt!")
        return
    encrypted = fernet.encrypt(text.encode())
    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, encrypted.decode())

def decrypt_text():
    text = input_text.get("1.0", tk.END).strip()
    try:
        decrypted = fernet.decrypt(text.encode())
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, decrypted.decode())
    except Exception as e:
        messagebox.showerror("Error", "Decryption failed! Check input.")

def encrypt_file():
    filepath = filedialog.askopenfilename()
    if not filepath:
        return
    with open(filepath, "rb") as file:
        data = file.read()
    encrypted = fernet.encrypt(data)
    with open(filepath + ".enc", "wb") as file:
        file.write(encrypted)
    messagebox.showinfo("Success", f"Encrypted file saved as {filepath}.enc")

def decrypt_file():
    filepath = filedialog.askopenfilename()
    if not filepath:
        return
    with open(filepath, "rb") as file:
        data = file.read()
    try:
        decrypted = fernet.decrypt(data)
    except:
        messagebox.showerror("Error", "Decryption failed!")
        return
    save_path = filedialog.asksaveasfilename(defaultextension=".txt")
    if save_path:
        with open(save_path, "wb") as file:
            file.write(decrypted)
        messagebox.showinfo("Success", f"Decrypted file saved as {save_path}")

# ================== GUI ==================
def create_gui():
    root = tk.Tk()
    root.title("Basic Encryption/Decryption Tool")
    root.geometry("600x500")
    root.config(bg="#f0f0f0")

    tk.Label(root, text="Input Text:", bg="#f0f0f0").pack()
    global input_text
    input_text = tk.Text(root, height=6, width=60)
    input_text.pack()

    btn_frame = tk.Frame(root, bg="#f0f0f0")
    btn_frame.pack(pady=10)

    tk.Button(btn_frame, text="Encrypt Text", command=encrypt_text).grid(row=0, column=0, padx=10)
    tk.Button(btn_frame, text="Decrypt Text", command=decrypt_text).grid(row=0, column=1, padx=10)

    tk.Label(root, text="Output Text:", bg="#f0f0f0").pack()
    global output_text
    output_text = tk.Text(root, height=6, width=60)
    output_text.pack()

    tk.Label(root, text="File Encryption/Decryption", font=('Arial', 12, 'bold'), bg="#f0f0f0").pack(pady=10)
    file_btn_frame = tk.Frame(root, bg="#f0f0f0")
    file_btn_frame.pack()

    tk.Button(file_btn_frame, text="Encrypt File", command=encrypt_file).grid(row=0, column=0, padx=10)
    tk.Button(file_btn_frame, text="Decrypt File", command=decrypt_file).grid(row=0, column=1, padx=10)

    root.mainloop()

# Optional password protection
def password_prompt():
    def check_password():
        if password_entry.get() == "admin123":
            prompt.destroy()
            create_gui()
        else:
            messagebox.showerror("Access Denied", "Incorrect Password!")

    prompt = tk.Tk()
    prompt.title("Password Required")
    prompt.geometry("300x150")
    tk.Label(prompt, text="Enter Password:").pack(pady=10)
    password_entry = tk.Entry(prompt, show="*", width=25)
    password_entry.pack()
    tk.Button(prompt, text="Login", command=check_password).pack(pady=10)
    prompt.mainloop()

# Run tool
password_prompt()  # You can replace with create_gui() to remove password protection
