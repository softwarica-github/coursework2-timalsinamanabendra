import os
import tkinter as tk
from tkinter import filedialog, messagebox, Listbox

class MaliciousFileScannerApp:
    def __init__(self, root):
        self.root = root
        self.directory = ""
        self.setup_ui()

    def setup_ui(self):
        self.root.title("Malicious File Scanner")
        self.root.geometry("600x400")

        frame = tk.Frame(self.root)
        frame.pack(pady=20)

        # Listbox to display the results
        self.listbox = Listbox(frame, width=80, height=20)
        self.listbox.pack(side="left", fill="y")

        scrollbar = tk.Scrollbar(frame, orient="vertical")
        scrollbar.config(command=self.listbox.yview)
        scrollbar.pack(side="right", fill="y")

        self.listbox.config(yscrollcommand=scrollbar.set)

        # Button to select directory and automatically start scan
        select_dir_button = tk.Button(self.root, text="Select Directory and Auto Scan", command=self.select_directory_and_scan)
        select_dir_button.pack(pady=5)

    def select_directory_and_scan(self):
        self.directory = filedialog.askdirectory()
        if self.directory:
            self.listbox.delete(0, tk.END)  # Clear existing entries
            self.listbox.insert(tk.END, f"Scanning directory: {self.directory}")
            self.start_scan()

    def start_scan(self):
        if self.directory:
            malicious_files = self.scan_files(self.directory)
            self.listbox.delete(0, tk.END)  # Clear existing entries for scan results
            if malicious_files:
                for file in malicious_files:
                    self.listbox.insert(tk.END, file)
                messagebox.showinfo("Scan completed", "Malicious files detected.")
            else:
                messagebox.showinfo("Scan completed", "No malicious files detected.")

    def scan_files(self, directory):
        detected_files = []
        
        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.endswith('.txt') or file.endswith('.MOV'):
                    file_path = os.path.join(root, file)
                    detected_files.append(file_path)
                    
        return detected_files

# Setting up the GUI
root = tk.Tk()
app = MaliciousFileScannerApp(root)
root.mainloop()
