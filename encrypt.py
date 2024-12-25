import os
import json
import base64
import random
import string
from linecache import cache
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def generate_key(password: str, salt: bytes) -> bytes:
    return base64.b64encode(PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    ).derive(password.encode()))


def random_string(length: int = 8) -> str:
    return ''.join(random.choices(string.ascii_letters, k=length))


def encrypt_bytes(data: bytes, password: str, salt: bytes) -> bytes:
    return Fernet(generate_key(password, salt)).encrypt(data)


def decrypt_bytes(data: bytes, password: str, salt: bytes) -> bytes:
    return Fernet(generate_key(password, salt)).decrypt(data)


def encrypt(src: str, dest: str, password: str) -> None:
    print(f"Encrypting {src} to {dest}")
    src_path = Path(src)
    dest_path = Path(dest)

    if src_path.is_file():
        salt = os.urandom(16)
        with open(src_path, 'rb') as f:
            content = f.read()
        with open(__file__, 'rb') as f:
            script = f.read()

        encrypted = encrypt_bytes(content, password, salt)
        data = {
            'salt': base64.b64encode(salt).decode(),
            'content': base64.b64encode(encrypted).decode(),
            'filename': base64.b64encode(src_path.name.encode()).decode(),
            'script': base64.b64encode(script).decode()
        }

        with open(dest_path / f"{random_string()}.enc", 'w') as f:
            json.dump(data, f)

    else:
        new_folder = dest_path / random_string()
        new_folder.mkdir(parents=True, exist_ok=True)

        salt = os.urandom(16)
        encrypted_name = encrypt_bytes(src_path.name.encode(), password, salt)

        with open(new_folder / '.folder_name_encrypted', 'w') as f:
            json.dump({
                'salt': base64.b64encode(salt).decode(),
                'name': base64.b64encode(encrypted_name).decode()
            }, f)

        for child in src_path.iterdir():
            encrypt(str(child), str(new_folder), password)


def decrypt(src: str, dest: str, password: str) -> None:
    print(f"Decrypting {src} to {dest}")
    src_path = Path(src)
    dest_path = Path(dest)

    if src_path.is_file():
        with open(src_path) as f:
            data = json.load(f)

        salt = base64.b64decode(data['salt'])
        content = base64.b64decode(data['content'])
        filename = base64.b64decode(data['filename']).decode()

        decrypted = decrypt_bytes(content, password, salt)
        with open(dest_path / filename, 'wb') as f:
            f.write(decrypted)

    else:
        folder_name = ""
        try:
            with open(src_path / '.folder_name_encrypted') as f:
                data = json.load(f)

            salt = base64.b64decode(data['salt'])
            encrypted_name = base64.b64decode(data['name'])
            folder_name = decrypt_bytes(encrypted_name, password, salt).decode()
        except:
            folder_name = dest
        new_folder = dest_path / folder_name
        new_folder.mkdir(parents=True, exist_ok=True)

        for child in src_path.iterdir():
            if child.name != '.folder_name_encrypted':
                decrypt(str(child), str(new_folder), password)

if __name__ == '__main__':
    cmd = input("encrypt?decrypt? [e/d]")
    if cmd != 'e' and cmd != 'd':
        print("arg error.")
        exit(1)
    psw = input("password: ")
    src = input("src: ")
    if len(src) == 0:
        print("src is empty.")
        exit(1)
    dest = input("dest: ")
    if len(dest) == 0:
        dest = src + ("_encrypted" if cmd == 'e' else "_decrypted")
    if cmd == 'e':
        encrypt(src, dest, psw)
    if cmd == 'd':
        decrypt(src, dest, psw)
