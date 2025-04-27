import os
import socket, struct, sys, os, hashlib, random
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding

AUTH_TOKEN = b"super_secure_token"

with open("public_key.pem", "rb") as f:
    public_key = serialization.load_pem_public_key(f.read())

SECRET_KEY = b"my_shared_secret"
KEY = sha256(SECRET_KEY).digest()[:16]
IV = b'InitializationVe'

encrypted_key = public_key.encrypt(
    KEY,
    rsa_padding.OAEP(
        mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

if len(sys.argv) != 4:
    print("Kullanım: python client.py <SERVER_IP> <DOSYA_YOLU> <BOZUK_PAKET_SAYISI>")
    sys.exit(1)

SERVER_IP = sys.argv[1]
FILE_NAME = sys.argv[2]
FILE_PATH = os.path.join("FilesToSend",FILE_NAME)
BOZUK_PAKET_SAYISI = int(sys.argv[3])
PORT = 5001
CHUNK_SIZE = 1024

file_size = os.path.getsize(FILE_PATH)
total_chunks = (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE
bozuk_paketler = random.sample(range(total_chunks), min(BOZUK_PAKET_SAYISI, total_chunks))
print(f"[~] Bozulacak parçalar: {bozuk_paketler}")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((SERVER_IP, PORT))

    # 🔹 1. Kimlik doğrulama
    s.send(struct.pack('!I', len(AUTH_TOKEN)))
    s.sendall(AUTH_TOKEN)

    # 🔹 2. Dosya adı gönder
    file_name = os.path.basename(FILE_PATH).encode()
    s.send(struct.pack('!I', len(file_name)))
    s.sendall(file_name)

    # 🔹 3. AES anahtar gönder (RSA ile şifreli)
    s.send(struct.pack('!I', len(encrypted_key)))
    s.sendall(encrypted_key)

    # 🔹 4. Parça sayısı gönder
    s.send(struct.pack('!I', total_chunks))

    # 🔹 5. Dosyayı gönder
    with open(FILE_PATH, 'rb') as f:
        for seq in range(total_chunks):
            chunk = f.read(CHUNK_SIZE)
            cipher = AES.new(KEY, AES.MODE_CBC, IV)
            encrypted = cipher.encrypt(pad(chunk, AES.block_size))
            hash_digest = sha256(encrypted).digest()

            if seq in bozuk_paketler:
                encrypted = b'Z' * len(encrypted)

            header = struct.pack('!II', seq, len(encrypted)) + hash_digest
            s.sendall(header)
            s.sendall(encrypted)

            durum = "BOZUK" if seq in bozuk_paketler else "OK"
            print(f"--> Gönderildi: {seq+1}/{total_chunks} [{durum}]")

print("[✓] Dosya transferi tamamlandı.")
