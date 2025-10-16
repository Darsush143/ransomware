import os
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet

# -----------------------------
# Utility Functions
# -----------------------------
def load_password_key(folder):
    """Reads the password and key from the saved file."""
    password_file = os.path.join(folder, "password.txt")

    if not os.path.exists(password_file):
        messagebox.showerror(
            "Missing File",
            "The password file (password.txt) is missing in the selected folder.\n"
            "Decryption cannot proceed without it."
        )
        return None, None

    try:
        with open(password_file, "r") as f:
            lines = f.readlines()
            password = lines[0].split(": ")[1].strip()
            key = lines[1].split(": ")[1].strip()
        return password, key
    except Exception as e:
        messagebox.showerror("Error", f"Error reading the password file:\n{e}")
        return None, None


def decrypt_files(folder):
    """Decrypts all .enc files in the selected folder using the stored key."""
    saved_password, key = load_password_key(folder)
    if not key:
        return

    try:
        cipher = Fernet(key.encode())
    except Exception:
        messagebox.showerror("Invalid Key", "The key in password.txt is invalid or corrupted.")
        return

    decrypted_count = 0
    failed_count = 0

    for root, _, files in os.walk(folder):
        for file in files:
            if file.endswith(".enc"):
                file_path = os.path.join(root, file)
                decrypted_file_path = os.path.splitext(file_path)[0]

                try:
                    with open(file_path, "rb") as f:
                        encrypted_data = f.read()

                    decrypted_data = cipher.decrypt(encrypted_data)

                    with open(decrypted_file_path, "wb") as f:
                        f.write(decrypted_data)

                    os.remove(file_path)
                    decrypted_count += 1

                except Exception as e:
                    failed_count += 1
                    print(f"[ERROR] Failed to decrypt {file_path}: {e}")

    if decrypted_count > 0:
        if failed_count > 0:
            messagebox.showwarning(
                "Decryption Completed with Errors",
                f"✅ Decrypted {decrypted_count} file(s)\n⚠️ Failed to decrypt {failed_count} file(s)"
            )
        else:
            messagebox.showinfo("Decryption Complete",
                                f"✅ Successfully decrypted {decrypted_count} file(s)!")
    else:
        messagebox.showinfo("No Encrypted Files Found",
                            "No '.enc' files were found in the selected folder.")


def select_folder():
    """Prompts the user to select a folder and starts the decryption process."""
    folder_selected = filedialog.askdirectory(title="Select Folder Containing Encrypted Files")

    if not folder_selected:
        messagebox.showwarning("No Folder Selected", "Please select a folder to proceed with decryption.")
        return

    decrypt_files(folder_selected)


# -----------------------------
# Fullscreen Animated UI
# -----------------------------
def setup_ui():
    root = tk.Tk()
    root.title("🔐 Secure File Decryption Utility")
    root.configure(bg="#1e1e2e")
    root.state('zoomed')  # Start maximized
    root.attributes('-alpha', 0.0)  # Start invisible for fade-in
    root.resizable(True, True)

    # Fade-in animation
    def fade_in(alpha=0.0):
        if alpha < 1.0:
            alpha += 0.05
            root.attributes('-alpha', alpha)
            root.after(30, fade_in, alpha)
    fade_in()

    # Center frame
    main_frame = tk.Frame(root, bg="#1e1e2e")
    main_frame.place(relx=0.5, rely=0.5, anchor="center")

    # Title
    title_label = tk.Label(
        main_frame,
        text="File Decryption Utility",
        font=("Segoe UI", 28, "bold"),
        fg="#00ffff",
        bg="#1e1e2e"
    )
    title_label.pack(pady=30)

    # Description
    desc = tk.Label(
        main_frame,
        text="This tool will automatically decrypt all '.enc' files\n"
             "in the selected folder using your stored encryption key.",
        font=("Segoe UI", 14),
        fg="#cccccc",
        bg="#1e1e2e",
        justify="center"
    )
    desc.pack(pady=10)

    # Glow frame
    glow_frame = tk.Frame(main_frame, bg="#00ff88", bd=0, highlightthickness=0)
    glow_frame.pack(pady=30)

    # Main button
    decrypt_button = tk.Button(
        glow_frame,
        text="Select Folder to Decrypt Files",
        command=select_folder,
        bg="#00cc66",
        fg="black",
        activebackground="#00ff88",
        activeforeground="black",
        font=("Segoe UI", 14, "bold"),
        width=40,
        height=2,
        relief="flat",
        cursor="hand2"
    )
    decrypt_button.pack()

    # Hover effect
    def on_enter(e):
        decrypt_button.config(bg="#00ff88")
        glow_frame.config(bg="#00ffff")

    def on_leave(e):
        decrypt_button.config(bg="#00cc66")
        glow_frame.config(bg="#00ff88")

    decrypt_button.bind("<Enter>", on_enter)
    decrypt_button.bind("<Leave>", on_leave)

    # Pulsing glow animation
    def pulse(alpha=0):
        color = f"#{int(0x00 + alpha):02x}ff{int(0x88 - alpha/2):02x}"
        glow_frame.config(bg=color)
        next_alpha = (alpha + 10) % 255
        root.after(80, pulse, next_alpha)
    pulse()

    # Title color animation
    def pulse_title(bright=0):
        color = f"#00{int(255 - bright/2):02x}ff"
        title_label.config(fg=color)
        next_bright = (bright + 15) % 255
        root.after(100, pulse_title, next_bright)
    pulse_title()

    # Footer
    footer = tk.Label(
        root,
        text="© 2025 SecureTech Solutions | Authorized Access Only",
        font=("Segoe UI", 10),
        fg="#888888",
        bg="#1e1e2e"
    )
    footer.pack(side="bottom", pady=10)

    root.mainloop()


# -----------------------------
# Entry Point
# -----------------------------
if __name__ == "__main__":
    setup_ui()
