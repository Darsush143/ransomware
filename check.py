import os
import time
import smtplib
import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox
from email.message import EmailMessage
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from cryptography.fernet import Fernet

# Email Configuration
ADMIN_EMAIL = "welabs448@gmail.com"
EMAIL_PASSWORD = "izht onbx azpv saue"
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

# Suspicious File Extensions
SUSPICIOUS_EXTENSIONS = ['.locked', '.encrypted', '.ransomed', '.payup', '.bitcoin', '.data', '.enc']

# -----------------------------
# Event Handler
# -----------------------------
class RansomwareDetectionHandler(FileSystemEventHandler):
    def __init__(self, log_callback, send_email_callback, decrypt_callback):
        self.log_callback = log_callback
        self.send_email_callback = send_email_callback
        self.decrypt_callback = decrypt_callback

    def on_modified(self, event):
        if not event.is_directory:
            file_path = event.src_path
            _, extension = os.path.splitext(file_path)
            if extension.lower() in SUSPICIOUS_EXTENSIONS:
                self.log_callback(f"[WARNING] Suspicious file detected: {file_path}")
                self.send_email_callback(file_path)
                self.decrypt_callback()

    def on_created(self, event):
        if not event.is_directory:
            file_path = event.src_path
            self.log_callback(f"[INFO] New file detected: {file_path}")
            ransom_notes = ["README.txt", "DECRYPT_FILES.txt", "HOW_TO_RECOVER.txt"]
            if any(note.lower() in file_path.lower() for note in ransom_notes):
                self.log_callback(f"[ALERT] Possible ransom note detected: {file_path}")
                self.send_email_callback(file_path)
                self.decrypt_callback()


# -----------------------------
# Main App
# -----------------------------
class RansomwareMonitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ Ransomware Detection System")
        self.root.state("zoomed")  # Fullscreen
        self.root.configure(bg="#1e1e2e")

        # Title with glow animation
        self.title_label = tk.Label(
            root,
            text="🛡️ Ransomware Detection & Protection",
            font=("Segoe UI", 24, "bold"),
            fg="#00ffff",
            bg="#1e1e2e"
        )
        self.title_label.pack(pady=15)
        self.pulse_title(0)

        # Main Frame
        main_frame = tk.Frame(root, bg="#1e1e2e")
        main_frame.pack(fill="both", expand=True, padx=20, pady=10)

        # Folder Frame
        folder_frame = tk.LabelFrame(main_frame, text="📁 Folder Monitoring", 
                                     bg="#25253a", fg="#00ffff", font=("Segoe UI", 12, "bold"))
        folder_frame.pack(fill="x", pady=10)

        tk.Label(folder_frame, text="Monitor Folder:", bg="#25253a", fg="white", font=("Segoe UI", 11)).grid(row=0, column=0, padx=5, pady=5)
        self.folder_entry = tk.Entry(folder_frame, width=60, font=("Segoe UI", 11))
        self.folder_entry.grid(row=0, column=1, padx=5, pady=5)

        self.browse_button = tk.Button(folder_frame, text="Browse", command=self.browse_folder,
                                       bg="#0078d7", fg="white", font=("Segoe UI", 11, "bold"), relief="flat", cursor="hand2")
        self.browse_button.grid(row=0, column=2, padx=5, pady=5)

        # Email Frame
        email_frame = tk.LabelFrame(main_frame, text="📧 Alert Email Configuration", 
                                    bg="#25253a", fg="#00ffff", font=("Segoe UI", 12, "bold"))
        email_frame.pack(fill="x", pady=10)

        tk.Label(email_frame, text="Recipient Email:", bg="#25253a", fg="white", font=("Segoe UI", 11)).grid(row=0, column=0, padx=5, pady=5)
        self.email_entry = tk.Entry(email_frame, width=60, font=("Segoe UI", 11))
        self.email_entry.grid(row=0, column=1, padx=5, pady=5)

        # Protection Checkbox
        self.protection_var = tk.BooleanVar()
        self.protection_checkbox = tk.Checkbutton(email_frame, text="Activate Auto Decrypt Protection",
                                                  variable=self.protection_var, bg="#25253a", fg="#00ff99",
                                                  selectcolor="#1e1e2e", font=("Segoe UI", 11, "bold"))
        self.protection_checkbox.grid(row=1, column=0, columnspan=2, pady=5)

        # Start Button with glossy effect
        self.start_button = tk.Button(main_frame, text="🚀 Start Monitoring", command=self.start_monitoring,
                                      bg="#00cc66", fg="black", font=("Segoe UI", 13, "bold"),
                                      activebackground="#00ff88", width=25, height=2, relief="flat", cursor="hand2")
        self.start_button.pack(pady=15)
        self.glossy_button_animation(self.start_button)

        # Log Frame
        log_frame = tk.LabelFrame(main_frame, text="📜 System Logs", bg="#25253a", fg="#00ffff", font=("Segoe UI", 12, "bold"))
        log_frame.pack(fill="both", expand=True, pady=10)

        self.output_text = scrolledtext.ScrolledText(log_frame, width=100, height=20, bg="#1e1e2e", fg="#00ff99",
                                                     insertbackground="white", font=("Consolas", 11))
        self.output_text.pack(padx=5, pady=5, fill="both", expand=True)

        # Hover effects
        for btn in [self.browse_button, self.start_button]:
            btn.bind("<Enter>", lambda e, b=btn: b.config(bg="#00aaff"))
            btn.bind("<Leave>", lambda e, b=btn: b.config(bg="#0078d7" if b==self.browse_button else "#00cc66"))

        self.observer = None

    # -----------------------------
    # Animations
    # -----------------------------
    def pulse_title(self, val):
        color = f"#00{255 - val:02x}ff"
        self.title_label.config(fg=color)
        self.root.after(100, self.pulse_title, (val+10) % 255)

    def glossy_button_animation(self, btn):
        # simple gradient pulse simulation
        def pulse(alpha=0):
            r = int(0 + alpha//2)
            g = int(204 + alpha//3)
            b = int(102 + alpha//4)
            color = f"#{r:02x}{g:02x}{b:02x}"
            btn.config(bg=color)
            self.root.after(80, pulse, (alpha+15) % 255)
        pulse()

    # -----------------------------
    # Functionality
    # -----------------------------
    def browse_folder(self):
        folder_selected = filedialog.askdirectory()
        self.folder_entry.delete(0, tk.END)
        self.folder_entry.insert(0, folder_selected)

    def log_message(self, message):
        self.output_text.insert(tk.END, message + "\n")
        self.output_text.see(tk.END)

    def send_alert_email(self, suspect_file):
        recipient_email = self.email_entry.get().strip()
        if not recipient_email:
            self.log_message("[ERROR] Please enter a recipient email!")
            return
        msg = EmailMessage()
        msg["Subject"] = "🚨 Ransomware Alert: Suspicious File Detected!"
        msg["From"] = ADMIN_EMAIL
        msg["To"] = recipient_email
        msg.set_content(f"⚠️ Suspicious file detected: {suspect_file}\n📅 Timestamp: {time.ctime()}\n")
        try:
            server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
            server.starttls()
            server.login(ADMIN_EMAIL, EMAIL_PASSWORD)
            server.send_message(msg)
            server.quit()
            self.log_message(f"[ALERT SENT] Suspicious file: {suspect_file}")
        except Exception as e:
            self.log_message(f"[EMAIL ERROR] Failed to send alert: {e}")

    def decrypt_files(self):
        if not self.protection_var.get():
            return
        folder = self.folder_entry.get().strip()
        if not folder:
            self.log_message("[ERROR] No folder selected for decryption!")
            return
        password_file = os.path.join(folder, "password.txt")
        if not os.path.exists(password_file):
            self.log_message("[ERROR] Password file missing! Cannot decrypt.")
            return
        with open(password_file, "r") as f:
            lines = f.readlines()
            key = lines[1].split(": ")[1].strip()
        cipher = Fernet(key.encode())
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
                        self.log_message(f"[DECRYPTED] {file_path} → {decrypted_file_path}")
                    except Exception as e:
                        self.log_message(f"[ERROR] Failed to decrypt {file_path}: {e}")
        self.log_message("✅ Files have been successfully decrypted!")

    def start_monitoring(self):
        monitor_folder = self.folder_entry.get().strip()
        if not os.path.isdir(monitor_folder):
            self.log_message("[ERROR] Invalid folder path!")
            return
        self.log_message(f"🚀 Monitoring folder: {monitor_folder}")
        event_handler = RansomwareDetectionHandler(self.log_message, self.send_alert_email, self.decrypt_files)
        self.observer = Observer()
        self.observer.schedule(event_handler, monitor_folder, recursive=True)
        self.observer.start()
        self.start_button.config(state=tk.DISABLED)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def on_close(self):
        if self.observer:
            self.observer.stop()
            self.observer.join()
        self.root.destroy()


# -----------------------------
# Program Entry
# -----------------------------
if __name__ == "__main__":
    root = tk.Tk()
    app = RansomwareMonitorApp(root)
    root.mainloop()
