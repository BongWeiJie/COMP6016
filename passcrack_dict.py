import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import random
import string
import concurrent.futures
import time

# Custom Hashing Algorithms Function
def custom_hash(password, algorithm="sha256"):
    if algorithm == "sha256":
        return hashlib.sha256(password.encode()).hexdigest()
    elif algorithm == "md5":
        return hashlib.md5(password.encode()).hexdigest()
    # Add support for other hashing algorithms as needed
    else:
        return None

# Export Results Function (Placeholder, export to a text file)
def export_results(cracked_passwords):
    with open("cracked_passwords.txt", "w") as f:
        for result in cracked_passwords:
            hash_str, password, _ = result  # Unpack the tuple
            f.write(f"Hash: {hash_str}, Password: {password}\n")
    messagebox.showinfo("Export Complete", "Cracked passwords exported to 'cracked_passwords.txt'.")

# Password Generator Function
def generate_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))

# Cracking Function with Multi-threading
def crack_passwords(hashes_file, dictionary_file, threads=1, hash_algorithm="sha256", time_elapsed_label=None, word_list_window=None):
    def worker(hash_str, dictionary, attempted_words):
        for word in dictionary:
            word = word.strip()
            try:
                hashed_word = custom_hash(word, hash_algorithm)
            except UnicodeDecodeError:
                continue  # Skip the word if decoding fails
            attempted_words.append(word)  # Record all attempted words
            if hashed_word == hash_str:
                print(f"Cracked Password: {word}")
                return (hash_str, word, attempted_words)
        return None

    with open(hashes_file, 'r') as f:
        hashes = f.readlines()

    cracked_passwords = []
    start_time = time.time()  # Record start time
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_hash = {executor.submit(worker, hash_str.strip(), open(dictionary_file, 'r', errors='ignore').readlines(), []): hash_str.strip() for hash_str in hashes}
        for future in concurrent.futures.as_completed(future_to_hash):
            result = future.result()
            if result is not None:
                cracked_passwords.append(result)
                elapsed_time = time.time() - start_time
                if time_elapsed_label:
                    time_elapsed_label.config(text=f"Time Elapsed: {elapsed_time:.2f} seconds")
                if word_list_window:
                    # Update the list with the first 100 attempted words
                    for word in result[2][:100]:
                        word_list_window.insert(tk.END, f"{word}\n")
                    word_list_window.see(tk.END)  # Auto-scroll to the end
    end_time = time.time()  # Record end time
    time_elapsed = end_time - start_time

    if cracked_passwords:
        messagebox.showinfo("Cracking Complete", "Passwords cracked successfully.")
    else:
        messagebox.showinfo("Cracking Complete", "No passwords cracked.")

    # Update time elapsed label
    if time_elapsed_label:
        time_elapsed_label.config(text=f"Time Elapsed: {time_elapsed:.2f} seconds")

    return cracked_passwords, time_elapsed

# GUI Functions
def browse_files(entry_widget):
    file_path = filedialog.askopenfilename()
    entry_widget.delete(0, tk.END)
    entry_widget.insert(0, file_path)

def generate_and_display_password():
    length = int(password_length_entry.get())
    password = generate_password(length)
    generated_password_entry.delete(0, tk.END)
    generated_password_entry.insert(0, password)

def start_cracking():
    hashes_file = hashes_entry.get()
    dictionary_file = dictionary_entry.get()

    if not hashes_file or not dictionary_file:
        show_error("Please select both files.")
        return

    if threads_entry.get():
        try:
            threads = int(threads_entry.get())
            if threads <= 0:
                raise ValueError
        except ValueError:
            show_error("Invalid number of threads. Please enter a positive integer.")
            return
    else:
        threads = 1

    selected_algorithm = algorithm_combobox.get()

    # Reset time labels
    time_elapsed_label.config(text="Time Elapsed: ")

    # Create word list window
    word_list_window = tk.Toplevel(window)
    word_list_window.title("Attempted Words")
    word_list_window.geometry("300x400")

    # Create word list label
    word_list_label = tk.Label(word_list_window, text="Attempted Words:")
    word_list_label.pack()

    # Create word list text widget
    word_list_text = tk.Text(word_list_window, height=20, width=40)
    word_list_text.pack()

    cracked_passwords, time_elapsed = crack_passwords(hashes_file, dictionary_file, threads=threads, hash_algorithm=selected_algorithm, time_elapsed_label=time_elapsed_label, word_list_window=word_list_text)

    if cracked_passwords:
        formatted_passwords = "\n".join(f"Hash: {hash_str}, Password: {password}" for hash_str, password, _ in cracked_passwords)
        messagebox.showinfo("Cracking Complete", f"Cracked Passwords:\n{formatted_passwords}")
        export_results(cracked_passwords)  # Export cracked passwords

    # Update time elapsed label
    time_elapsed_label.config(text=f"Time Elapsed: {time_elapsed:.2f} seconds")

# Generate Hash Function
def generate_hash():
    password = password_entry.get()
    selected_algorithm = algorithm_combobox.get()
    hashed_password = custom_hash(password, selected_algorithm)
    if hashed_password:
        hashed_password_entry.config(state="normal")
        hashed_password_entry.delete(0, tk.END)
        hashed_password_entry.insert(0, hashed_password)
        hashed_password_entry.config(state="readonly")
    else:
        messagebox.showinfo("Error", "Hashing algorithm not supported")

# Create the main window
window = tk.Tk()
window.title("Password Cracker")

# Create widgets
hashes_label = tk.Label(window, text="Hashes File:")
hashes_entry = tk.Entry(window, width=50)
hashes_browse_button = tk.Button(window, text="Browse", command=lambda: browse_files(hashes_entry))

dictionary_label = tk.Label(window, text="Dictionary File:")
dictionary_entry = tk.Entry(window, width=50)
dictionary_browse_button = tk.Button(window, text="Browse", command=lambda: browse_files(dictionary_entry))

threads_label = tk.Label(window, text="Threads (optional):")
threads_entry = tk.Entry(window, width=10)

password_length_label = tk.Label(window, text="Password Length:")
password_length_entry = tk.Entry(window, width=10)
generate_button = tk.Button(window, text="Generate Password", command=generate_and_display_password)
generated_password_entry = tk.Entry(window, width=50)

password_label = tk.Label(window, text="Password:")
password_entry = tk.Entry(window, width=50)

generate_hash_button = tk.Button(window, text="Generate Hash", command=generate_hash)

algorithm_label = tk.Label(window, text="Hashing Algorithm:")
algorithms = ["sha256", "md5"]  # Add more algorithms here if needed
algorithm_combobox = ttk.Combobox(window, values=algorithms)
algorithm_combobox.current(0)

hashed_password_label = tk.Label(window, text="Hashed Password:")
hashed_password_entry = tk.Entry(window, width=50, state="readonly")

time_elapsed_label = tk.Label(window, text="Time Elapsed: ")

start_button = tk.Button(window, text="Start Cracking", command=start_cracking)

# Place widgets in the window
hashes_label.grid(row=0, column=0, padx=10, pady=10)
hashes_entry.grid(row=0, column=1, padx=10, pady=10)
hashes_browse_button.grid(row=0, column=2, padx=10, pady=10)

dictionary_label.grid(row=1, column=0, padx=10, pady=10)
dictionary_entry.grid(row=1, column=1, padx=10, pady=10)
dictionary_browse_button.grid(row=1, column=2, padx=10, pady=10)

threads_label.grid(row=2, column=0, padx=10, pady=10)
threads_entry.grid(row=2, column=1, padx=10, pady=10)

password_length_label.grid(row=3, column=0, padx=10, pady=10)
password_length_entry.grid(row=3, column=1, padx=10, pady=10)
generate_button.grid(row=3, column=2, padx=10, pady=10)
generated_password_entry.grid(row=3, column=3, padx=10, pady=10)

password_label.grid(row=4, column=0, padx=10, pady=10)
password_entry.grid(row=4, column=1, padx=10, pady=10)
generate_hash_button.grid(row=4, column=2, padx=10, pady=10)

algorithm_label.grid(row=4, column=3, padx=10, pady=10)
algorithm_combobox.grid(row=4, column=4, padx=10, pady=10)

hashed_password_label.grid(row=5, column=0, padx=10, pady=10)
hashed_password_entry.grid(row=5, column=1, padx=10, pady=10)

time_elapsed_label.grid(row=6, column=0, padx=10, pady=10)

start_button.grid(row=7, column=0, columnspan=5, padx=10, pady=10)

# Start the GUI event loop
window.mainloop()


