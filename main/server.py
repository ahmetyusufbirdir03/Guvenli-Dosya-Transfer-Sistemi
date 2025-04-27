import os
import socket, struct, hashlib
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding

AUTH_TOKEN = b"super_secure_token"

with open("private_key.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

HOST = '0.0.0.0'
PORT = 5001

def recv_exact(conn, size):
    data = b''
    while len(data) < size:
        packet = conn.recv(size - len(data))
        if not packet:
            raise ConnectionError("Bağlantı beklenmedik şekilde kapandı.")
        data += packet
    return data

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen(1)
    print(f"[+] Dinleniyor: {HOST}:{PORT}")

    
    conn, addr = s.accept()
    with conn:
        print(f"[+] Bağlantı: {addr}")

        try:
            # 🔹 1. Kimlik doğrulama
            token_len = struct.unpack('!I', recv_exact(conn, 4))[0]
            received_token = recv_exact(conn, token_len)
            if received_token != AUTH_TOKEN:
                print("!!! Hatalı kimlik doğrulama. Bağlantı reddedildi.")
                conn.close()
                
            print("[+] Kimlik doğrulama başarılı.")

                # 🔹 2. Dosya adını al
            file_name_len = struct.unpack('!I', recv_exact(conn, 4))[0]
            file_name = recv_exact(conn, file_name_len).decode()
            print(f"[+] Alınan dosya adı: {file_name}")

            # 🔹 Sadece uzantıyı koru
            file_name = os.path.join("RecievedFiles", file_name)

            # 🔹 3. AES anahtarını al ve çöz
            key_len = struct.unpack('!I', recv_exact(conn, 4))[0]
            encrypted_key = recv_exact(conn, key_len)
            KEY = private_key.decrypt(
                encrypted_key,
                rsa_padding.OAEP(
                    mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            IV = b'InitializationVe'

            # 🔹 4. Parça sayısını al
            total_chunks, = struct.unpack('!I', recv_exact(conn, 4))

            error_count = 0
            with open(file_name, 'wb') as f:
                for _ in range(total_chunks):
                    header = recv_exact(conn, 40)
                    seq, length = struct.unpack('!II', header[:8])
                    recv_hash = header[8:]

                    encrypted = recv_exact(conn, length)
                    calc_hash = sha256(encrypted).digest()

                    if calc_hash != recv_hash:
                        print(f"!!! Hash uyumsuz: Parça {seq+1}")
                        error_count += 1
                        continue

                    cipher = AES.new(KEY, AES.MODE_CBC, IV)
                    try:
                        decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)
                        f.write(decrypted)
                        print(f"<-- Alındı: {seq+1}/{total_chunks}")
                    except ValueError:
                        print(f"!!! Şifre çözüm hatası: Parça {seq+1}")
                        error_count += 1

            print(f"\n[+] Transfer tamamlandı. Toplam hata: {error_count}")

        except Exception as e:
            print(f"!!! Hata: {e}")
