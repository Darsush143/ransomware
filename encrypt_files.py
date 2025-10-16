import os
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
import random
import string

# -----------------------------
# Utility Functions
# -----------------------------
def generate_password(length=16):
    """Generates a secure random password."""
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(chars) for _ in range(length))


def encrypt_files(folder):
    """Encrypts all files in the selected folder using a randomly generated key."""
    password = generate_password()
    key = Fernet.generate_key()
    cipher = Fernet(key)
    password_file = os.path.join(folder, "password.txt")

    try:
        with open(password_file, "w") as f:
            f.write(f"Password: {password}\n")
            f.write(f"Key: {key.decode()}\n")

        encrypted_count = 0
        failed_count = 0

        for root, _, files in os.walk(folder):
            for file in files:
                file_path = os.path.join(root, file)

                if file.endswith(".enc") or file == "password.txt":
                    continue

                try:
                    with open(file_path, "rb") as f:
                        data = f.read()

                    encrypted_data = cipher.encrypt(data)

                    with open(file_path + ".enc", "wb") as f:
                        f.write(encrypted_data)

                    os.remove(file_path)
                    encrypted_count += 1

                except Exception as e:
                    failed_count += 1
                    print(f"[ERROR] Failed to encrypt {file_path}: {e}")

        messagebox.showinfo(
            "Encryption Complete",
            f"✅ Successfully encrypted {encrypted_count} file(s).\n"
            f"⚠️ Failed to encrypt {failed_count} file(s)." if failed_count else
            f"✅ Successfully encrypted {encrypted_count} file(s).\n\n🔑 Password and key saved in:\n{password_file}"
        )

    except Exception as e:
        messagebox.showerror("Error", f"An error occurred during encryption:\n{e}")


def select_folder():
    """Opens a dialog for folder selection and starts encryption."""
    folder_selected = filedialog.askdirectory(title="Select Folder to Encrypt")

    if not folder_selected:
        messagebox.showwarning("No Folder Selected", "Please select a folder to proceed.")
        return

    confirm = messagebox.askyesno(
        "Confirm Encryption",
        "Are you sure you want to encrypt all files in this folder?\n"
        "⚠️ This process cannot be undone without the password file."
    )

    if confirm:
        encrypt_files(folder_selected)
    else:
        messagebox.showinfo("Cancelled", "Encryption cancelled.")


# -----------------------------
# UI Setup (Fullscreen + Animations)
# -----------------------------
def setup_ui():
    root = tk.Tk()
    root.title("🔒 Secure File Encryption Utility")
    root.configure(bg="#1e1e2e")
    root.state('zoomed')  # 🔹 Open in fullscreen mode
    root.attributes('-alpha', 0.0)  # Start invisible for fade-in animation

    # Fade-in animation
    def fade_in(alpha=0.0):
        if alpha < 1.0:
            alpha += 0.05
            root.attributes('-alpha', alpha)
            root.after(30, fade_in, alpha)
    fade_in()

    # Main center frame
    main_frame = tk.Frame(root, bg="#1e1e2e")
    main_frame.place(relx=0.5, rely=0.5, anchor="center")

    # Title with glow
    title_label = tk.Label(
        main_frame,
        text="File Encryption Utility",
        font=("Segoe UI", 28, "bold"),
        fg="#ff5555",
        bg="#1e1e2e"
    )
    title_label.pack(pady=30)

    # Description
    desc_label = tk.Label(
        main_frame,
        text="Encrypt all files in a selected folder using strong encryption.\n"
             "A password and key file will be generated automatically.",
        font=("Segoe UI", 14),
        fg="#cccccc",
        bg="#1e1e2e",
        justify="center"
    )
    desc_label.pack(pady=10)

    # Glow frame for button
    glow_frame = tk.Frame(main_frame, bg="#ff7777", bd=0, highlightthickness=0)
    glow_frame.pack(pady=30)

    # Main button
    encrypt_button = tk.Button(
        glow_frame,
        text="Select Folder to Encrypt Files",
        command=select_folder,
        bg="#ff5555",
        fg="white",
        activebackground="#ff7777",
        activeforeground="white",
        font=("Segoe UI", 14, "bold"),
        width=40,
        height=2,
        relief="flat",
        cursor="hand2"
    )
    encrypt_button.pack()

    # Hover effects
    def on_enter(e):
        encrypt_button.config(bg="#ff7777")
        glow_frame.config(bg="#ff9999")

    def on_leave(e):
        encrypt_button.config(bg="#ff5555")
        glow_frame.config(bg="#ff7777")

    encrypt_button.bind("<Enter>", on_enter)
    encrypt_button.bind("<Leave>", on_leave)

    # Button glow pulse animation
    def pulse(alpha=0):
        color = f"#ff{int(85 + alpha//2):02x}{int(85 + alpha//3):02x}"
        glow_frame.config(bg=color)
        root.after(80, pulse, (alpha + 15) % 255)
    pulse()

    # Title glow pulse animation
    def pulse_title(bright=0):
        color = f"#ff{int(85 + bright//3):02x}{int(85 + bright//5):02x}"
        title_label.config(fg=color)
        root.after(100, pulse_title, (bright + 20) % 255)
    pulse_title()

    # Disclaimer
    disclaimer = tk.Label(
        main_frame,
        text="⚠️ Keep the generated password.txt file safe. It is required for decryption.",
        font=("Segoe UI", 10),
        fg="#bbbbbb",
        bg="#1e1e2e",
        wraplength=600,
        justify="center"
    )
    disclaimer.pack(pady=10)

    # Footer
    footer = tk.Label(
        root,
        text="© 2025 SecureTech Solutions | Confidential Use Only",
        font=("Segoe UI", 10),
        fg="#666666",
        bg="#1e1e2e"
    )
    footer.pack(side="bottom", pady=10)

    root.mainloop()


# -----------------------------
# Entry Point
# -----------------------------
if __name__ == "__main__":
    setup_ui()
