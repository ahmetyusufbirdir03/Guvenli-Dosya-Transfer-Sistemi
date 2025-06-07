import os
import socket
import struct
import threading
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
import subprocess
import signal
import atexit

# Basit kimlik doğrulama için kullanılan sabit token
AUTH_TOKEN = b"super_secure_token"

# Sunucunun dinleyeceği IP ve portlar
HOST = '0.0.0.0'  # Tüm ağ arayüzlerinden gelen bağlantıları kabul et
TCP_PORT = 5001
UDP_PORT = 5002

# iperf3 işlemlerini yönetmek için global değişkenler
iperf3_proc_5001 = None  # 5001 portu için iperf3 süreci
iperf3_proc_5002 = None  # 5002 portu için iperf3 süreci
iperf3_path = "../Tools/iperf3.exe"  # iperf3 yürütülebilir dosyasının yolu

# RSA private key'i dosyadan yükleniyor (gelen AES anahtarını çözmek için gerekli)
try:
    with open("private_key.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
except FileNotFoundError:
    print("Hata: private_key.pem dosyası bulunamadı. Lütfen sunucu dizinine koyun.")
    exit(1) # Dosya yoksa programı sonlandır
except Exception as e:
    print(f"Hata: Özel anahtar yüklenirken bir sorun oluştu: {e}")
    exit(1)

# Belirli bir boyutta veri alınana kadar soketten okuma yapan yardımcı fonksiyon (TCP için)
def recv_exact(conn, size):
    data = b''
    while len(data) < size:
        packet = conn.recv(size - len(data))
        if not packet:
            # Karşı taraf bağlantıyı beklenmedik şekilde kapattığında hata fırlat
            raise ConnectionError("Bağlantı beklenmedik şekilde kapandı.")
        data += packet
    return data

# iperf3 sunucularını belirtilen portlarda arka planda başlatır (ağ performansı ölçümü için)
def start_iperf3_servers():
    global iperf3_proc_5001, iperf3_proc_5002
    print("Starting iperf3 server on port 5001...")
    # subprocess.Popen ile iperf3'ü yeni bir süreç olarak başlat
    iperf3_proc_5001 = subprocess.Popen(
        [iperf3_path, '-s', '-p', '5001'],
        stdout=subprocess.DEVNULL,  # Standart çıktıyı gizle
        stderr=subprocess.DEVNULL   # Hata çıktısını gizle
    )

    print("Starting iperf3 server on port 5002...")
    iperf3_proc_5002 = subprocess.Popen(
        [iperf3_path, '-s', '-p', '5002'],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    print("iperf3 servers are running on ports 5001 and 5002.")

# Çalışan iperf3 sunucularını güvenli bir şekilde durdurur
def stop_iperf3_servers():
    global iperf3_proc_5001, iperf3_proc_5002
    print("Stopping iperf3 servers...")
    if iperf3_proc_5001:
        iperf3_proc_5001.send_signal(signal.SIGINT) # SIGINT sinyali göndererek iperf3'ü durdur
        iperf3_proc_5001.wait() # Sürecin sonlanmasını bekle
    if iperf3_proc_5002:
        iperf3_proc_5002.send_signal(signal.SIGINT)
        iperf3_proc_5002.wait()

# TCP üzerinden şifreli dosya alımını yöneten sunucu fonksiyonu
def tcp_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, TCP_PORT)) # Belirtilen IP ve portta dinlemeye başla
        s.listen(1) # Tek bir bağlantıyı kuyruğa alabilir
        print(f"[TCP] Dinleniyor: {HOST}:{TCP_PORT}")

        while True:
            conn, addr = s.accept() # Bağlantıyı kabul et
            with conn: # Bağlantı sona erdiğinde otomatik kapanmasını sağlar
                print(f"[TCP] Bağlantı: {addr}")

                try:
                    # Kimlik doğrulama token'ı alınıyor
                    token_len = struct.unpack('!I', recv_exact(conn, 4))[0] # Token uzunluğunu oku
                    received_token = recv_exact(conn, token_len) # Tokenı oku
                    if received_token != AUTH_TOKEN:
                        print("[TCP] Hatalı kimlik doğrulama. Bağlantı kapatılıyor.")
                        conn.close()
                        continue # Bir sonraki bağlantıyı bekle

                    # Dosya adı alınıyor
                    file_name_len = struct.unpack('!I', recv_exact(conn, 4))[0] # Dosya adı uzunluğunu oku
                    file_name = recv_exact(conn, file_name_len).decode() # Dosya adını oku ve çöz
                    os.makedirs("../RecievedFiles", exist_ok=True) # Dosyaların kaydedileceği dizini oluştur
                    file_path = os.path.join("../RecievedFiles", file_name) # Dosya için tam yol

                    # RSA ile şifrelenmiş AES anahtarı çözülüyor
                    key_len = struct.unpack('!I', recv_exact(conn, 4))[0] # Şifreli anahtarın uzunluğunu oku
                    encrypted_key = recv_exact(conn, key_len) # Şifreli anahtarı oku
                    KEY = private_key.decrypt( # Özel anahtar ile AES anahtarını çöz
                        encrypted_key,
                        rsa_padding.OAEP(
                            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    IV = b'InitializationVe'  # Sabit IV 
                    total_chunks, = struct.unpack('!I', recv_exact(conn, 4)) # Toplam parça sayısını oku

                    with open(file_path, 'wb') as f: # Dosyayı yazma modunda aç
                        for _ in range(total_chunks):
                            # Her bir parça için: başlık (sıra numarası, uzunluk, hash)
                            header = recv_exact(conn, 40) # 40 byte'lık başlığı oku (4 byte sıra, 4 byte uzunluk, 32 byte hash)
                            seq, length = struct.unpack('!II', header[:8]) # Sıra numarasını ve şifreli verinin uzunluğunu çöz
                            recv_hash = header[8:] # Gelen hash değerini al
                            encrypted = recv_exact(conn, length) # Şifreli veri içeriğini oku

                            # SHA256 ile veri bütünlüğü kontrolü
                            calc_hash = sha256(encrypted).digest()
                            if calc_hash != recv_hash:
                                print(f"[TCP] Hash hatası tespit edildi: Parça {seq}. Bu parça atlanıyor.")
                                # TCP'de tekrar deneme mekanizması bulunmadığından, bozuk parça atlanır
                                continue

                            # AES CBC ile çözümleme ve dosyaya yazma
                            cipher = AES.new(KEY, AES.MODE_CBC, IV)
                            decrypted = unpad(cipher.decrypt(encrypted), AES.block_size) # Veriyi çöz ve padding'i kaldır
                            f.write(decrypted) # Çözülmüş veriyi dosyaya yaz
                            print(f"[TCP] Parça alındı ve yazıldı: {seq+1}/{total_chunks}")

                    print(f"[TCP] Dosya alımı tamamlandı: {file_name}")

                except ConnectionError as ce:
                    print(f"[TCP] Bağlantı hatası: {ce}")
                except Exception as e:
                    print(f"[TCP] Bir hata oluştu: {e}")

# UDP ile güvenilir dosya alımını yöneten sunucu fonksiyonu
def udp_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((HOST, UDP_PORT)) # Belirtilen IP ve UDP portunda dinlemeye başla
    print(f"[UDP] Dinleniyor: {HOST}:{UDP_PORT}")

    file_obj = None # Açık dosya nesnesi
    KEY = None # AES anahtarı
    IV = b'InitializationVe' # Sabit IV
    received_chunks = {} # Alınan parçaları sıra numarasına göre tutan sözlük
    expected_total = None # Beklenen toplam parça sayısı
    addr = None  # Şu anki dosya transferini yapan istemcinin adresi (tek istemci varsayımı)

    while True:
        try:
            data, sender_addr = sock.recvfrom(65535) # Gelen UDP paketini oku
        except ConnectionResetError as e:
            # Windows'da bazen UDP soketinde ConnectionResetError alınabilir
            print(f"[UDP] ConnectionResetError alındı: {e}. Dinlemeye devam ediliyor.")
            continue

        # Yeni bir dosya transferi başlangıcı sinyali
        if data.startswith(b"FILENAME:"):
            # Önceki transferden kalan veri varsa kapat ve sıfırla
            if file_obj:
                file_obj.close()
                print("[UDP] Yeni dosya transferi başladığı için önceki dosya işlemi kapatıldı.")
            
            addr = sender_addr # İlk mesajı gönderen istemciyi kaydet
            file_name = data[len(b"FILENAME:"):].decode() # Dosya adını çöz
            os.makedirs("../RecievedFiles", exist_ok=True) # Kayıt dizinini oluştur
            file_path = os.path.join("../RecievedFiles", file_name)
            file_obj = open(file_path, "wb") # Dosyayı yazma modunda aç
            received_chunks.clear() # Önceki parçaları temizle
            expected_total = None # Beklenen toplam parça sayısını sıfırla
            print(f"[UDP] Dosya adı alındı: {file_name}")

        # Yalnızca mevcut transferin yapıldığı istemciden gelen paketleri işle
        if addr is not None and sender_addr != addr:
            print(f"[UDP] Başka bir adresten (farklı oturum?) gelen paket atlandı: {sender_addr}")
            continue

        # AES anahtarı alımı
        if data.startswith(b"KEY:"):
            KEY = data[len(b"KEY:"):] # Gelen AES anahtarını al
            print("[UDP] AES anahtarı alındı.")

        # Veri parçası alımı
        elif data.startswith(b"CHUNK:"):
            header_len = len(b"CHUNK:")
            seq = struct.unpack('!I', data[header_len:header_len+4])[0] # Sıra numarasını al
            recv_hash = data[header_len+4:header_len+36] # Gelen hash değerini al
            encrypted = data[header_len+36:] # Şifreli veri içeriğini al

            # Bütünlük kontrolü (SHA256 hash)
            calc_hash = sha256(encrypted).digest()
            if calc_hash != recv_hash:
                print(f"[UDP] Hash uyuşmazlığı: Parça {seq}, NACK gönderiliyor.")
                sock.sendto(b"NACK:" + struct.pack('!I', seq), addr) # NACK göndererek tekrar iste
                continue # Bu parçayı işleme

            # Parça henüz alınmamışsa kaydet ve ACK gönder
            if seq not in received_chunks:
                received_chunks[seq] = encrypted # Parçayı bellekte sakla
                sock.sendto(struct.pack('!I', seq), addr) # ACK (Onay) gönder
                print(f"[UDP] Parça alındı ve ACK gönderildi: {seq}")
            else:
                # Zaten alınmış bir parça gelirse tekrar ACK gönder (tekrarlayan ACK'lar)
                sock.sendto(struct.pack('!I', seq), addr)
                print(f"[UDP] Tekrarlayan parça {seq} alındı, ACK tekrar gönderildi.")

        # Dosya transferi sonu sinyali
        elif data.startswith(b"END:"):
            expected_total = int(data[len(b"END:"):]) # Beklenen toplam parça sayısını al
            print(f"[UDP] Transfer tamamlandı sinyali alındı. Beklenen parça sayısı: {expected_total}")

            if file_obj and KEY:
                # Tüm parçaların alınıp alınmadığını kontrol et ve dosyaya yaz
                is_complete = True
                for i in range(expected_total):
                    if i not in received_chunks:
                        print(f"[UDP] Eksik parça: {i}. Dosya tamamlanamadı.")
                        is_complete = False
                        break
                    
                    encrypted = received_chunks[i]
                    cipher = AES.new(KEY, AES.MODE_CBC, IV)
                    try:
                        decrypted = unpad(cipher.decrypt(encrypted), AES.block_size) # Veriyi çöz ve padding'i kaldır
                        file_obj.write(decrypted) # Çözülmüş veriyi dosyaya yaz
                    except Exception as e:
                        print(f"[UDP] Şifre çözme hatası: Parça {i}: {e}. Bu parça atlanıyor.")
                        is_complete = False
                        break
                
                if is_complete:
                    print(f"[UDP] Dosya başarıyla kaydedildi: {file_obj.name}")
                
                file_obj.close() # Dosya nesnesini kapat
                # Transfer sonrası durumu sıfırla
                file_obj = None
                KEY = None
                received_chunks.clear()
                expected_total = None
                addr = None # Yeni transfer için adres sıfırlanıyor
            else:
                print("[UDP] Dosya objesi veya anahtar mevcut değil, dosya yazılamadı.")

if __name__ == "__main__":
    # Sunucu başlatıldığında iperf3 sunucularını da başlat
    start_iperf3_servers()
    atexit.register(stop_iperf3_servers)

    # TCP ve UDP işlemleri için ayrı thread'ler başlatılıyor
    tcp_thread = threading.Thread(target=tcp_server, daemon=True) # daemon=True ile ana program kapanınca thread'ler de kapanır
    udp_thread = threading.Thread(target=udp_server, daemon=True)

    tcp_thread.start()
    udp_thread.start()

    print("[*] Server başlatıldı. TCP ve UDP dinleniyor...")

    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("\n[!] Server kapatılıyor...")