"""
Secure SHA-256 File/Data Integrity Checker
CNS Mini Project

Author: Aayushi Gurav
Purpose:
    Calculate a SHA-256 digest for a file and compare it with a trusted
    reference digest to detect accidental or unauthorized modification.

Security notes:
    - Files are opened only for reading.
    - Files are never executed or modified by this application.
    - Hashing is performed in chunks to reduce memory usage.
    - A maximum file size can be configured to avoid accidental resource abuse.
"""

import hashlib
import re
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

MAX_FILE_SIZE = 500 * 1024 * 1024  # 500 MB safety limit
CHUNK_SIZE = 1024 * 1024           # 1 MB


def validate_sha256(value: str) -> bool:
    """Return True only for a valid 64-hex-character SHA-256 digest."""
    return bool(re.fullmatch(r"[0-9a-fA-F]{64}", value.strip()))


def calculate_sha256(file_path: str) -> str:
    """Calculate SHA-256 using chunked reading."""
    path = Path(file_path)

    if not path.is_file():
        raise ValueError("The selected path is not a valid file.")

    size = path.stat().st_size
    if size > MAX_FILE_SIZE:
        raise ValueError("File is larger than the 500 MB safety limit.")

    digest = hashlib.sha256()
    with path.open("rb") as file:
        while True:
            chunk = file.read(CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)

    return digest.hexdigest()


def save_hash_file(file_path: str, digest: str) -> str:
    """Save a standard .sha256 reference file beside the selected file."""
    path = Path(file_path)
    output = path.with_name(path.name + ".sha256")
    output.write_text(f"{digest}  {path.name}\n", encoding="utf-8")
    return str(output)


def read_hash_file(hash_path: str) -> str:
    """Read and validate a SHA-256 value from a .sha256/text file."""
    content = Path(hash_path).read_text(encoding="utf-8", errors="strict").strip()
    match = re.search(r"(?i)(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])", content)
    if not match:
        raise ValueError("No valid 64-character SHA-256 hash was found.")
    return match.group(0).lower()


class IntegrityCheckerApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("SecurePass? No — SHA-256 File Integrity Checker")
        self.root.geometry("820x620")
        self.root.minsize(720, 560)

        self.file_path = tk.StringVar()
        self.current_hash = tk.StringVar()
        self.reference_hash = tk.StringVar()
        self.status = tk.StringVar(value="Select a file to begin.")

        self._build_style()
        self._build_ui()

    def _build_style(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Title.TLabel", font=("Segoe UI", 20, "bold"))
        style.configure("Subtitle.TLabel", font=("Segoe UI", 10))
        style.configure("Card.TLabelframe", padding=14)
        style.configure("Action.TButton", padding=(14, 8))
        style.configure("Status.TLabel", font=("Segoe UI", 11, "bold"))

    def _build_ui(self):
        container = ttk.Frame(self.root, padding=24)
        container.pack(fill="both", expand=True)

        ttk.Label(container, text="SHA-256 File Integrity Checker",
                  style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            container,
            text="Verify whether a file has remained unchanged using cryptographic hashing.",
            style="Subtitle.TLabel"
        ).pack(anchor="w", pady=(2, 18))

        file_box = ttk.LabelFrame(container, text="1. Select File", style="Card.TLabelframe")
        file_box.pack(fill="x", pady=(0, 12))

        row = ttk.Frame(file_box)
        row.pack(fill="x")
        ttk.Entry(row, textvariable=self.file_path, state="readonly").pack(
            side="left", fill="x", expand=True, padx=(0, 10)
        )
        ttk.Button(row, text="Browse", command=self.choose_file,
                   style="Action.TButton").pack(side="right")

        action_box = ttk.LabelFrame(container, text="2. Calculate Integrity Hash",
                                     style="Card.TLabelframe")
        action_box.pack(fill="x", pady=(0, 12))

        buttons = ttk.Frame(action_box)
        buttons.pack(fill="x")
        ttk.Button(buttons, text="Calculate SHA-256",
                   command=self.calculate, style="Action.TButton").pack(side="left")
        ttk.Button(buttons, text="Save Hash Reference",
                   command=self.save_reference, style="Action.TButton").pack(side="left", padx=8)

        ttk.Label(action_box, text="Current SHA-256:").pack(anchor="w", pady=(12, 4))
        current_entry = ttk.Entry(action_box, textvariable=self.current_hash, state="readonly")
        current_entry.pack(fill="x")

        compare_box = ttk.LabelFrame(container, text="3. Compare With Trusted Hash",
                                      style="Card.TLabelframe")
        compare_box.pack(fill="x", pady=(0, 12))

        ref_row = ttk.Frame(compare_box)
        ref_row.pack(fill="x")
        ttk.Entry(ref_row, textvariable=self.reference_hash).pack(
            side="left", fill="x", expand=True, padx=(0, 10)
        )
        ttk.Button(ref_row, text="Load .sha256 File",
                   command=self.load_reference).pack(side="left")
        ttk.Button(ref_row, text="Compare",
                   command=self.compare, style="Action.TButton").pack(side="left", padx=(8, 0))

        result_box = ttk.LabelFrame(container, text="Result", style="Card.TLabelframe")
        result_box.pack(fill="both", expand=True)

        ttk.Label(result_box, textvariable=self.status,
                  style="Status.TLabel", wraplength=700).pack(anchor="w", pady=(4, 12))

        info = (
            "CNS concepts demonstrated:\n"
            "• SHA-256 cryptographic hashing\n"
            "• Data integrity verification\n"
            "• Collision-resistance concept\n"
            "• Input validation and secure file handling\n\n"
            "Important: SHA-256 is a hash function, not encryption. "
            "The original file cannot be recovered from its hash."
        )
        ttk.Label(result_box, text=info, justify="left", wraplength=700).pack(anchor="w")

    def choose_file(self):
        path = filedialog.askopenfilename(title="Select a file to verify")
        if not path:
            return

        try:
            p = Path(path)
            if p.stat().st_size > MAX_FILE_SIZE:
                messagebox.showerror(
                    "File Too Large",
                    "Please select a file up to 500 MB."
                )
                return
        except OSError as exc:
            messagebox.showerror("File Error", str(exc))
            return

        self.file_path.set(str(p))
        self.current_hash.set("")
        self.status.set("File selected. Click 'Calculate SHA-256'.")

    def calculate(self):
        path = self.file_path.get().strip()
        if not path:
            messagebox.showwarning("No File", "Please select a file first.")
            return

        try:
            digest = calculate_sha256(path)
            self.current_hash.set(digest)
            self.status.set("✓ SHA-256 calculated successfully. Keep this value as the trusted reference.")
        except (ValueError, OSError) as exc:
            messagebox.showerror("Hashing Error", str(exc))

    def save_reference(self):
        path = self.file_path.get().strip()
        digest = self.current_hash.get().strip()

        if not path:
            messagebox.showwarning("No File", "Please select a file first.")
            return
        if not validate_sha256(digest):
            messagebox.showwarning("No Hash", "Calculate a valid SHA-256 hash first.")
            return

        try:
            saved = save_hash_file(path, digest)
            messagebox.showinfo("Reference Saved", f"Trusted hash saved to:\n{saved}")
            self.status.set("✓ Reference hash file created.")
        except OSError as exc:
            messagebox.showerror("Save Error", str(exc))

    def load_reference(self):
        path = filedialog.askopenfilename(
            title="Select SHA-256 reference file",
            filetypes=[("Hash/Text files", "*.sha256 *.txt"), ("All files", "*.*")]
        )
        if not path:
            return

        try:
            digest = read_hash_file(path)
            self.reference_hash.set(digest)
            self.status.set("Reference hash loaded. Click 'Compare'.")
        except (ValueError, OSError) as exc:
            messagebox.showerror("Reference Error", str(exc))

    def compare(self):
        path = self.file_path.get().strip()
        reference = self.reference_hash.get().strip().lower()

        if not path:
            messagebox.showwarning("No File", "Please select a file first.")
            return
        if not validate_sha256(reference):
            messagebox.showwarning(
                "Invalid Hash",
                "Enter exactly 64 hexadecimal characters or load a valid .sha256 file."
            )
            return

        try:
            actual = calculate_sha256(path)
            self.current_hash.set(actual)

            if actual.lower() == reference:
                self.status.set("✓ INTEGRITY VERIFIED — The file matches the trusted SHA-256 hash.")
                messagebox.showinfo(
                    "Integrity Verified",
                    "The calculated SHA-256 matches the trusted reference.\n\n"
                    "No modification was detected by this hash comparison."
                )
            else:
                self.status.set("✗ INTEGRITY CHECK FAILED — The file does not match the trusted hash.")
                messagebox.showwarning(
                    "Modification Detected",
                    "The calculated SHA-256 does not match the trusted reference.\n\n"
                    "The file may have been modified or the reference hash may be incorrect."
                )
        except (ValueError, OSError) as exc:
            messagebox.showerror("Comparison Error", str(exc))


def main():
    root = tk.Tk()
    IntegrityCheckerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
