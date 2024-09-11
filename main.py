import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from concurrent.futures import ProcessPoolExecutor as PPE
import dictscript 
import brutescript  
import time  

#This program uses ProcessPoolExecutor to speed up cracking process. However, it seems to only work for dictionary attack.

class PasswordCrackerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Cracker Tool")
        
        # Create Notebook (Tabs)
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(expand=True, fill='both')
        
        # Welcome Tab
        self.welcome_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.welcome_frame, text="Welcome")
        self.setup_welcome_tab()
        
        # Dictionary Attack Tab
        self.dictionary_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.dictionary_frame, text="Dictionary Attack")
        self.setup_dictionary_tab()
        
        # Brute-Force Attack Tab
        self.brute_force_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.brute_force_frame, text="Brute-Force Attack")
        self.setup_brute_force_tab()

    def setup_welcome_tab(self):
        tk.Label(self.welcome_frame, text="Welcome, User!", font=("Arial", 16)).pack(pady=10)
        
        self.attack_method_var = tk.StringVar(value="None")
        
        tk.Radiobutton(self.welcome_frame, text="Dictionary Attack", variable=self.attack_method_var, value="Dictionary Attack").pack(pady=5)
        tk.Radiobutton(self.welcome_frame, text="Brute-Force Attack", variable=self.attack_method_var, value="Brute-Force Attack").pack(pady=5)
        
        tk.Button(self.welcome_frame, text="Select", command=self.on_select).pack(pady=10)

    def setup_dictionary_tab(self):
        self.dictionary_file_path = tk.StringVar()
        self.hashed_passwords_file_path = tk.StringVar()
        self.algorithm = tk.StringVar(value="sha256")
        
        tk.Label(self.dictionary_frame, text="Dictionary Attack Settings").pack(pady=10)
        
        tk.Label(self.dictionary_frame, text="Hashed Passwords File:").pack()
        self.hashed_passwords_file_label = tk.Label(self.dictionary_frame, textvariable=self.hashed_passwords_file_path)
        self.hashed_passwords_file_label.pack(pady=5)
        tk.Button(self.dictionary_frame, text="Browse", command=self.load_hashed_passwords_file).pack(pady=5)
        
        tk.Label(self.dictionary_frame, text="Dictionary File:").pack()
        self.dictionary_file_label = tk.Label(self.dictionary_frame, textvariable=self.dictionary_file_path)
        self.dictionary_file_label.pack(pady=5)
        tk.Button(self.dictionary_frame, text="Browse", command=self.load_dictionary_file).pack(pady=5)
        
        tk.Label(self.dictionary_frame, text="Hashing Algorithm:").pack()
        ttk.Combobox(self.dictionary_frame, textvariable=self.algorithm, values=["sha256", "md5"]).pack(pady=5)
        
        self.timer_label_dict = tk.Label(self.dictionary_frame, text="Time Elapsed: 0s")
        self.timer_label_dict.pack(pady=5)
        
        tk.Button(self.dictionary_frame, text="Dictionary Crack", command=self.start_dictionary_crack).pack(pady=10)
    
    def setup_brute_force_tab(self):
        self.target_password = tk.StringVar()
        self.max_length = tk.IntVar(value=4)
        self.include_uppercase = tk.BooleanVar(value=True)
        self.include_lowercase = tk.BooleanVar(value=True)
        self.include_numbers = tk.BooleanVar(value=True)
        self.include_symbols = tk.BooleanVar(value=True)
        
        tk.Label(self.brute_force_frame, text="Brute-Force Attack Settings").pack(pady=10)
        
        tk.Label(self.brute_force_frame, text="Target Password:").pack()
        tk.Entry(self.brute_force_frame, textvariable=self.target_password, width=50).pack(pady=5)
        
        tk.Label(self.brute_force_frame, text="Max Length:").pack()
        tk.Entry(self.brute_force_frame, textvariable=self.max_length).pack(pady=5)
        
        tk.Checkbutton(self.brute_force_frame, text="Include Uppercase", variable=self.include_uppercase).pack(pady=5)
        tk.Checkbutton(self.brute_force_frame, text="Include Lowercase", variable=self.include_lowercase).pack(pady=5)
        tk.Checkbutton(self.brute_force_frame, text="Include Numbers", variable=self.include_numbers).pack(pady=5)
        tk.Checkbutton(self.brute_force_frame, text="Include Symbols", variable=self.include_symbols).pack(pady=5)
        
        self.timer_label_brute = tk.Label(self.brute_force_frame, text="Time Elapsed: 0s")
        self.timer_label_brute.pack(pady=5)
        
        tk.Button(self.brute_force_frame, text="Brute-Force Crack", command=self.start_brute_force_crack).pack(pady=10)
    
    def on_select(self):
        selected_method = self.attack_method_var.get()
        if selected_method == "Dictionary Attack":
            self.notebook.select(self.dictionary_frame)
        elif selected_method == "Brute-Force Attack":
            self.notebook.select(self.brute_force_frame)
        else:
            messagebox.showerror("Error", "Please select an attack method.")

    def load_dictionary_file(self):
        file_path = filedialog.askopenfilename(title="Select Dictionary File")
        if file_path:
            self.dictionary_file_path.set(file_path)
            self.dictionary_file_label.config(text=file_path)
    
    def load_hashed_passwords_file(self):
        file_path = filedialog.askopenfilename(title="Select Hashed Passwords File")
        if file_path:
            self.hashed_passwords_file_path.set(file_path)
            self.hashed_passwords_file_label.config(text=file_path)
    
    def start_dictionary_crack(self):
        hashed_passwords_file = self.hashed_passwords_file_path.get()
        dictionary_file = self.dictionary_file_path.get()
        algorithm = self.algorithm.get()

        if not hashed_passwords_file or not dictionary_file:
            messagebox.showerror("Error", "Please upload both files.")
            return
        
        self.timer_start_time_dict = time.perf_counter()
        with PPE() as executor:
            future = executor.submit(dictscript.dictionary_attack, hashed_passwords_file, dictionary_file, algorithm)
            result, elapsed_time = future.result()
            self.update_timer(self.timer_label_dict, elapsed_time)
        
        if result:
            result_str = "\n".join(f"Hash: {h} -> Password: {p}" for h, p in result.items())
            messagebox.showinfo("Success", f"Cracked Passwords:\n{result_str}")
        else:
            messagebox.showinfo("Result", "No passwords found.")
    
    def start_brute_force_crack(self):
        target_password = self.target_password.get()
        max_length = self.max_length.get()
        include_uppercase = self.include_uppercase.get()
        include_lowercase = self.include_lowercase.get()
        include_numbers = self.include_numbers.get()
        include_symbols = self.include_symbols.get()

        if not target_password:
            messagebox.showerror("Error", "Please enter the target password.")
            return
        
        self.timer_start_time_brute = time.perf_counter()
        with PPE() as executor:
            future = executor.submit(brutescript.brute_force_attack, target_password, max_length, include_uppercase, include_lowercase, include_numbers, include_symbols)
            result, elapsed_time = future.result()
            self.update_timer(self.timer_label_brute, elapsed_time)
        
        messagebox.showinfo("Result", f"Cracked Password: {result}")

    def update_timer(self, timer_label, elapsed_time):
        timer_label.config(text=f"Time Elapsed: {elapsed_time:.2f}s")

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordCrackerApp(root)
    root.mainloop()
