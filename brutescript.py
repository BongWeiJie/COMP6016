import time
import itertools
import string
import hashlib

def custom_hash(password, algorithm="sha256"):
    if algorithm == "sha256":
        return hashlib.sha256(password.encode()).hexdigest()
    elif algorithm == "md5":
        return hashlib.md5(password.encode()).hexdigest()
    else:
        return None

def brute_force_attack(target_password_plaintext, max_length=4, include_uppercase=True, include_lowercase=True, include_numbers=True, include_symbols=True, algorithm="sha256"):
    characters = ""
    if include_uppercase:
        characters += string.ascii_uppercase
    if include_lowercase:
        characters += string.ascii_lowercase
    if include_numbers:
        characters += string.digits
    if include_symbols:
        characters += string.punctuation

    if not characters:
        characters = string.ascii_letters + string.digits + string.punctuation

    # Hash the target plaintext password
    target_hash = custom_hash(target_password_plaintext, algorithm)

    def generate_combinations():
        for length in range(1, max_length + 1):
            for combo in itertools.product(characters, repeat=length):
                yield ''.join(combo)

    start_time = time.time()
    
    for password in generate_combinations():
        if custom_hash(password, algorithm) == target_hash:
            end_time = time.time()
            return password, end_time - start_time
    
    end_time = time.time()
    return None, end_time - start_time

# Example usage
if __name__ == "__main__":
    target_password = input("Enter the plaintext password to crack: ")
    max_length = int(input("Enter the maximum length of the password: "))
    include_uppercase = input("Include Uppercase? (y/n): ").strip().lower() == 'y'
    include_lowercase = input("Include Lowercase? (y/n): ").strip().lower() == 'y'
    include_numbers = input("Include Numbers? (y/n): ").strip().lower() == 'y'
    include_symbols = input("Include Symbols? (y/n): ").strip().lower() == 'y'
    algorithm = input("Enter hashing algorithm (sha256/md5): ").strip().lower()

    result, elapsed_time = brute_force_attack(
        target_password,
        max_length,
        include_uppercase,
        include_lowercase,
        include_numbers,
        include_symbols,
        algorithm
    )
    
    print(f"Result: {result}, Time Elapsed: {elapsed_time:.2f} seconds")

