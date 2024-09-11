import time
import hashlib

def custom_hash(password, algorithm="sha256"):
    if algorithm == "sha256":
        return hashlib.sha256(password.encode()).hexdigest()
    elif algorithm == "md5":
        return hashlib.md5(password.encode()).hexdigest()
    else:
        return None

def dictionary_attack(hashed_passwords_file, dictionary_file, algorithm):
    def worker(word):
        hashed_word = custom_hash(word.strip(), algorithm)
        return hashed_word
    
    start_time = time.perf_counter()
    
    # Read hashed passwords from file
    with open(hashed_passwords_file, 'r', errors='ignore') as f:
        hashed_passwords = set(line.strip() for line in f)
    
    # Process dictionary file
    found_passwords = {}
    with open(dictionary_file, 'r', errors='ignore') as f:
        dictionary = f.readlines()
    
    for word in dictionary:
        hashed_word = worker(word)
        if hashed_word in hashed_passwords:
            found_passwords[hashed_word] = word.strip()
    
    end_time = time.perf_counter()
    
    if found_passwords:
        return found_passwords, end_time - start_time
    
    return None, end_time - start_time
