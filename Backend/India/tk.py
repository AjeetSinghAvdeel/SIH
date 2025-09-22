import threading
print("[DEBUG] tk.py started")
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import os
import time
import sys

# import your core functions (main.py must be renamed to secure_wipe_core.py OR import from main)
try:
    from main import generate_keys, wipe_file, generate_certificate, verify_certificate
except Exception as e:
    raise SystemExit("Failed to import core functions. Ensure main.py is in the same folder.\n" + str(e))

APP_TITLE = "Secure Wipe — Demo UI"

class WipeUI:
    def __init__(self, root):
        self.root = root
        root.title(APP_TITLE)
        root.geometry("700x520")

        # Top frame: controls
        frm = tk.Frame(root, padx=10, pady=10)
        frm.pack(fill="x")

        tk.Label(frm, text="Target file/device (demo uses file):").grid(row=0, column=0, sticky="w")
        self.path_var = tk.StringVar()
        tk.Entry(frm, textvariable=self.path_var, width=60).grid(row=1, column=0, columnspan=3, sticky="w")
        tk.Button(frm, text="Browse", command=self.browse).grid(row=1, column=3, padx=6)

        tk.Label(frm, text="Passes:").grid(row=2, column=0, sticky="w", pady=(8,0))
        self.passes_var = tk.IntVar(value=1)
        tk.Spinbox(frm, from_=1, to=7, textvariable=self.passes_var, width=5).grid(row=2, column=1, sticky="w", pady=(8,0))

        self.method_var = tk.StringVar(value="Random Overwrite")
        tk.Label(frm, text="Method:").grid(row=2, column=2, sticky="e", pady=(8,0))
        tk.OptionMenu(frm, self.method_var, "Random Overwrite", "Zero Overwrite").grid(row=2, column=3, sticky="w", pady=(8,0))

        # Buttons
        btn_frame = tk.Frame(root, pady=8)
        btn_frame.pack(fill="x")
        tk.Button(btn_frame, text="Generate Keys", command=self.gen_keys).pack(side="left", padx=8)
        tk.Button(btn_frame, text="Wipe Now", command=self.start_wipe, bg="#d9534f", fg="white").pack(side="left", padx=8)
        tk.Button(btn_frame, text="Verify Last Cert", command=self.verify_last).pack(side="left", padx=8)
        tk.Button(btn_frame, text="Open Certs Folder", command=self.open_certs).pack(side="left", padx=8)

        # Log area
        tk.Label(root, text="Log / Output:").pack(anchor="w", padx=12)
        self.log = scrolledtext.ScrolledText(root, height=18, wrap="word", state="normal")
        self.log.pack(fill="both", padx=12, pady=(0,12), expand=True)

        # state
        self.last_cert_path = None

    def log_msg(self, *parts):
        msg = " ".join(str(p) for p in parts)
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        self.log.insert(tk.END, f"[{ts}] {msg}\n")
        self.log.see(tk.END)

    def browse(self):
        p = filedialog.askopenfilename(title="Select file to wipe (use test file!)")
        if p:
            self.path_var.set(p)

    def gen_keys(self):
        try:
            generate_keys()
            self.log_msg("Keys generated: private_key.pem (keep secret), public_key.pem (shareable).")
            messagebox.showinfo("Keys", "RSA key pair created (private_key.pem, public_key.pem).")
        except Exception as e:
            self.log_msg("Key generation failed:", e)
            messagebox.showerror("Error", str(e))

    def start_wipe(self):
        target = self.path_var.get().strip()
        if not target:
            messagebox.showwarning("No target", "Please select a target file/device first.")
            return
        if not os.path.exists(target):
            messagebox.showerror("Not found", "Target path does not exist.")
            return

        if not messagebox.askyesno("Confirm Wipe",
                f"Are you sure you want to wipe:\n{target}\n\n(Use only test files/devices!)"):
            return

        # Run wipe in background thread to keep UI responsive
        t = threading.Thread(target=self._wipe_thread, args=(target,))
        t.start()

    def _wipe_thread(self, target):
        passes = int(self.passes_var.get())
        method = self.method_var.get()
        try:
            self.log_msg("Starting wipe:", target, "| passes:", passes, "| method:", method)
            wipe_file(target, passes=passes)
            self.log_msg("Wipe finished. Creating signed certificate...")
            devname = os.path.basename(target)
            json_path, pdf_path = generate_certificate(devname, method, passes)
            self.last_cert_path = json_path
            self.log_msg("Certificate created:", json_path)
            self.log_msg("PDF created:", pdf_path)
            messagebox.showinfo("Success", f"Wipe complete.\nCertificate saved:\n{json_path}")
        except Exception as e:
            self.log_msg("Error during wipe:", e)
            messagebox.showerror("Error", str(e))

    def verify_last(self):
        if not self.last_cert_path:
            messagebox.showwarning("No certificate", "No certificate found from this session. Run a wipe first.")
            return
        try:
            ok = verify_certificate(self.last_cert_path)
            if ok:
                self.log_msg("Certificate verification: VALID")
                messagebox.showinfo("Verified", "Certificate is valid (signature OK).")
            else:
                self.log_msg("Certificate verification: INVALID")
                messagebox.showerror("Invalid", "Certificate verification failed.")
        except Exception as e:
            self.log_msg("Verification error:", e)
            messagebox.showerror("Error", str(e))

    def open_certs(self):
        out_dir = os.path.join(os.getcwd(), "certs")
        os.makedirs(out_dir, exist_ok=True)
        try:
            if os.name == "nt":
                os.startfile(out_dir)
            elif sys.platform == "darwin":
                os.system(f"open '{out_dir}'")
            else:
                os.system(f"xdg-open '{out_dir}'")
            self.log_msg("Opened certs folder:", out_dir)
        except Exception as e:
            self.log_msg("Could not open folder:", e)
            messagebox.showinfo("Folder", f"Certs folder: {out_dir}")

if __name__ == "__main__":
    print("[DEBUG] Creating Tk root window...")
    root = tk.Tk()
    app = WipeUI(root)
    print("[DEBUG] Entering mainloop...")
    root.mainloop()
    print("[DEBUG] mainloop exited.")

    root = tk.Tk()
    root.title("Tkinter Test")
    root.geometry("300x100")
    tk.Label(root, text="If you see this, Tkinter works!").pack(pady=20)
    root.mainloop()
