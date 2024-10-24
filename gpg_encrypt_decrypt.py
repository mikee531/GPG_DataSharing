import gnupg
import re
import os
from getpass import getpass

# Initialize the GPG object
gpg = gnupg.GPG()

def is_password_strong(password):
    """
    Check if the password meets the policy:
    - At least 12 characters long
    - Contains at least one number
    - Contains at least one uppercase letter
    - Contains at least one lowercase letter
    - Contains at least one special character
    """
    if len(password) < 12:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'[0-9]', password):
        return False
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False
    return True

def encrypt_file(input_file, password):
    """
    Encrypts the file using AES-256 encryption with a given password.
    """
    if not is_password_strong(password):
        print("Password is not strong enough! It must be at least 12 characters long, "
              "and include numbers, uppercase and lowercase letters, and special characters.")
        return
    
    with open(input_file, 'rb') as f:
        encrypted_data = gpg.encrypt_file(
            f,
            recipients=None,
            symmetric=True,
            passphrase=password,
            output=f"{input_file}.gpg",
            extra_args=['--cipher-algo', 'AES256']
        )
    
    if encrypted_data.ok:
        print(f"File '{input_file}' successfully encrypted as '{input_file}.gpg'.")
    else:
        print(f"Error encrypting the file: {encrypted_data.stderr}")

def decrypt_file(encrypted_file, password):
    """
    Decrypts the file using the provided password.
    """
    output_file = encrypted_file.replace('.gpg', '')
    with open(encrypted_file, 'rb') as f:
        decrypted_data = gpg.decrypt_file(
            f, passphrase=password, output=output_file
        )
    
    if decrypted_data.ok:
        print(f"File '{encrypted_file}' successfully decrypted as '{output_file}'.")
    else:
        print(f"Error decrypting the file: {decrypted_data.stderr}")

def main():
    # Get input for action (encrypt or decrypt)
    action = input("Do you want to (e)ncrypt or (d)ecrypt? ").lower()
    file_path = input("Enter the file path: ")
    
    if action == 'e':
        if not os.path.exists(file_path):
            print("File does not exist.")
            return
        password = getpass("Enter the encryption password: ")
        encrypt_file(file_path, password)
    
    elif action == 'd':
        if not os.path.exists(file_path) or not file_path.endswith('.gpg'):
            print("Encrypted file does not exist or is not a '.gpg' file.")
            return
        password = getpass("Enter the decryption password: ")
        decrypt_file(file_path, password)
    
    else:
        print("Invalid option. Please choose 'e' for encryption or 'd' for decryption.")

if __name__ == "__main__":
    main()
