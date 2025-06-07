import os, re, socket, struct, time, subprocess, platform, threading
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext

# -------------------- Global Değişkenler --------------------
selected_protocol = None  # Kullanıcının seçtiği protokol (TCP, UDP, HYBRID)
protocol_flag = None  # Kullanılan protokolü belirten bayrak: True = UDP, False = TCP
SERVER_IP = None  # Sunucu IP adresi
FILE_PATH = None  # Gönderilecek dosyanın yolu
log_widget = None  # GUI'deki log ekranı widget'ı
iperf3_path = "../Tools/iperf3.exe"  # iperf3 uygulamasının dosya yolu
iperf3_results = []  # iperf3 test sonuçlarını tutar
corrupt_packet_count_selected = 0 # GUI'den seçilen bozuk paket sayısı

# GUI log yazdırma fonksiyonu
def gui_log(message):
    # Log mesajını GUI'ye güvenli bir şekilde ekler
    def append_log():
        log_widget.configure(state='normal')  # Log widget'ını düzenlenebilir yap
        log_widget.insert(tk.END, message + '\n')  # Mesajı log'a ekle
        log_widget.see(tk.END)  # En sona kaydır
        log_widget.configure(state='disabled')  # Log'u tekrar kilitler
    root.after(0, append_log)  # GUI thread'inde çalıştır

# Belirtilen IP adresine ping atarak gecikmeyi ölçer
def measure_ping(ip):
    param = '-n' if platform.system().lower() == 'windows' else '-c'  # İşletim sistemine göre ping parametresi
    command = ['ping', param, '4', ip]  # Ping komutu (4 paket gönderilir)

    try:
        output = subprocess.check_output(command, universal_newlines=True)  # Ping çıktısını yakala
        gui_log("Ping testi çıktısı:\n" + output)  # Ping komutunun tüm çıktısını göster

        if platform.system().lower() == 'windows':
            match = re.search(r'Average = (\d+)ms', output)  # Windows çıktısında ortalama gecikmeyi bul
            if match:
                avg_delay = int(match.group(1))
                gui_log(f"Ortalama gecikme (ms): {avg_delay}")
                return avg_delay
        else:
            match = re.search(r'avg = ([\d\.]+)', output)  # Linux/macOS çıktısında ortalama gecikmeyi bul
            if match:
                avg_delay = float(match.group(1))
                gui_log(f"Ortalama gecikme (ms): {avg_delay}")
                return avg_delay
    except Exception as e:
        gui_log(f"Ping testi başarısız: {e}")
        return None

    gui_log("Ping sonucu bulunamadı.")
    return None

# iperf3 istemcisini çalıştırır ve sonuçları kaydeder
def run_iperf3_client(server_ip, port, gui_log):
    global iperf3_results
    gui_log(f"[iperf3] {port} portuna bağlanıyor...")
    cmd = [iperf3_path, '-c', server_ip, '-p', str(port), '-t', '10']  # iperf3 komutu (10 saniye test)
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    output_lines = []
    while True:
        output = proc.stdout.readline()  # iperf3 çıktısını satır satır oku
        if output == '' and proc.poll() is not None:
            break
        if output:
            output_lines.append(output.strip())

    proc.poll()  # Sürecin sonlandığından emin ol
    iperf3_results.append(f"[iperf3 port {port}]:\n" + "\n".join(output_lines))  # Sonuçları listeye ekle
    gui_log("[iperf3] Test sonuçları:\n" + "\n\n".join(iperf3_results))

# Dosya transferini ayrı bir thread'de başlatır
def start_transfer_thread():
    thread = threading.Thread(target=transfer_file)
    thread.daemon = True  # Ana program kapanınca thread'in de kapanmasını sağlar
    thread.start()

# Belirli sayıda veri paketini bozarak test için hazırlar
def corrupt_packets(data_packets, corrupt_count):
    import random
    total_packets = len(data_packets)
    if corrupt_count > total_packets:
        corrupt_count = total_packets
    
    corrupt_indices = random.sample(range(total_packets), corrupt_count)  # Bozmak için rastgele indeksler seç
    corrupted_packets = []

    for i, packet in enumerate(data_packets):
        if i in corrupt_indices:
            # Paketin ilk byte'ını değiştirerek bozar
            corrupted_packet = bytearray(packet)
            if len(corrupted_packet) > 0:
                corrupted_packet[0] ^= 0xFF  # İlk byte'ı ters çevir
            corrupted_packets.append(bytes(corrupted_packet))
            gui_log(f"[BOZUK] Paket {i} bozuldu.")
        else:
            corrupted_packets.append(packet)
    return corrupted_packets

# UDP paketini gönderir ve gerekirse tekrar dener (ACK/NACK mekanizması)
def send_packet_with_retries(seq, first_packet, original_packet, server_addr, sock, delay):
    retries = 0
    max_retries = 10  # Maksimum tekrar deneme sayısı
    sock.settimeout(0.5)  # Her deneme için zaman aşımı
    while retries < max_retries:
        # İlk denemede bozuk, tekrar denemelerde orijinal paket gönderilir
        to_send = first_packet if retries == 0 else original_packet

        # Paket içeriği: [CHUNK, sıralama numarası, hash, şifreli veri]
        hash_digest = to_send[-32:]  # Son 32 byte hash
        encrypted = to_send[:-32]  # Geri kalanı şifreli veri
        payload = b"CHUNK:" + struct.pack('!I', seq) + hash_digest + encrypted

        sock.sendto(payload, server_addr)
        time.sleep(delay)  # Gönderimler arasında kısa bir gecikme

        try:
            data, _ = sock.recvfrom(1024)  # Sunucudan ACK/NACK bekle
            if data.startswith(b"NACK:"):
                nack_seq = struct.unpack('!I', data[5:9])[0]
                if nack_seq == seq:
                    gui_log(f"[UDP] NACK alındı, paket {seq} tekrar gönderiliyor.")
                    retries += 1
                    continue  # Sonraki denemeye geç
            else:
                ack_seq = struct.unpack('!I', data)[0]
                if ack_seq == seq:
                    gui_log(f"[UDP] ACK alındı: {seq}")
                    break  # Başarılı, döngüden çık
        except socket.timeout:
            retries += 1
            gui_log(f"[UDP] Timeout, paket {seq} tekrar gönderiliyor ({retries}/{max_retries})")
    else:
        # Maksimum deneme aşıldığında hata fırlat
        gui_log(f"[UDP] Paket {seq} için maksimum tekrar aşıldı, transfer başarısız.")
        raise Exception(f"Paket {seq} gönderilemedi, transfer iptal ediliyor.")

# Dosya transfer işlemini yöneten ana fonksiyon
def transfer_file():
    global protocol_flag, SERVER_IP, FILE_PATH, corrupt_packet_count_selected, selected_protocol

    # Protokol seçimine göre bayrağı ayarla
    if selected_protocol == "HYBRID":
        gui_log("HYBRID protokol seçildi.")
        gui_log("Sunucuya ping atılıyor.")
        delay = measure_ping(SERVER_IP)  # Ping ölçümü yap
        if delay is None:
            gui_log("Ping testi başarısız oldu, lütfen IP adresini kontrol edin.")
            return # Ping testi başarısız olursa fonksiyonu sonlandır
        if delay < 100:  # Eşik değeri (ms cinsinden)
            gui_log("Gecikme 100ms'in altında olduğundan UDP protokolü seçildi.")
            protocol_flag = True
        else:
            gui_log("Gecikme 100ms'in üstünde olduğundan TCP protokolü seçildi.")
            protocol_flag = False
    elif selected_protocol == "UDP":
        protocol_flag = True
    else:  # TCP seçilmiş
        protocol_flag = False

    # Başlangıç gecikmesi (UDP için adaptif gecikme kontrolü)
    delay = 0.01
    min_delay = 0.005
    max_delay = 0.1

    # iperf3 testleri için kullanılacak portlar
    ports = [5001, 5002]
    iperf_threads = []
    
    # Her port için iperf3 testini ayrı thread'de başlat
    for port in ports:
        t = threading.Thread(target=run_iperf3_client, args=(SERVER_IP, port, gui_log))
        t.start()
        iperf_threads.append(t)

    # TCP ve UDP port numaraları
    TCP_PORT = 5001
    UDP_PORT = 5002

    # Her veri parçasının boyutu (1 KB)
    CHUNK_SIZE = 1024

    # Paylaşılan gizli anahtar ve IV (AES için)
    SECRET_KEY = b"my_shared_secret"
    IV = b'InitializationVe' # 16 byte IV

    # Dosya adını al
    FILE_NAME = os.path.basename(FILE_PATH)

    # Sunucunun public key'ini oku (RSA ile AES anahtarını şifrelemek için)
    try:
        with open("public_key.pem", "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
    except FileNotFoundError:
        gui_log("Hata: public_key.pem dosyası bulunamadı. Lütfen anahtar dosyasının doğru konumda olduğundan emin olun.")
        return
    except Exception as e:
        gui_log(f"Public key yüklenirken hata oluştu: {e}")
        return

    # Dosya boyutunu ve toplam chunk sayısını hesapla
    file_size = os.path.getsize(FILE_PATH)
    total_chunks = (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE

    # AES için 16 baytlık anahtar SHA256 ile türetilir
    KEY = sha256(SECRET_KEY).digest()[:16]

    # AES anahtarını sunucuya gönderebilmek için RSA ile şifrele
    encrypted_key = public_key.encrypt(
        KEY,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Dosya parçalarını oku, AES ile şifrele ve hash'le
    data_chunks = []
    with open(FILE_PATH, "rb") as f:
        for _ in range(total_chunks):
            chunk = f.read(CHUNK_SIZE)
            cipher = AES.new(KEY, AES.MODE_CBC, IV)  # Her blok için IV sabit
            encrypted = cipher.encrypt(pad(chunk, AES.block_size))
            hash_digest = sha256(encrypted).digest()  # Veri bütünlüğü için hash
            data_chunks.append((encrypted, hash_digest))

    # Kullanıcının GUI'den seçtiği bozuk paket sayısını al
    corrupt_count = corrupt_packet_count_selected
    gui_log(f"Bozuk paket sayısı: {corrupt_count}")

    # Paketleri hazırla (şifreli + hash), ardından bazılarını boz
    encrypted_packets = [enc + hsh for enc, hsh in data_chunks]
    corrupted_packets = corrupt_packets(encrypted_packets, corrupt_count)

    # -------------------- UDP Transferi --------------------
    if protocol_flag:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_addr = (SERVER_IP, UDP_PORT)

        gui_log(f"[UDP] Dosya gönderimi başlıyor: {FILE_NAME}")

        # Dosya adı ve AES anahtarı UDP ile gönderilir
        sock.sendto(b"FILENAME:" + FILE_NAME.encode(), server_addr)
        time.sleep(0.1) # Kısa bir bekleme
        sock.sendto(b"KEY:" + KEY, server_addr)
        time.sleep(0.1) # Kısa bir bekleme

        # Her paketi sırayla gönder
        for seq in range(len(encrypted_packets)):
            first_packet = corrupted_packets[seq]   # İlk gönderimde bozuk olabilir
            original_packet = encrypted_packets[seq]  # Sonraki tekrarlar için orijinal veri

            start = time.time()
            try:
                # Paketi gönder ve ACK/NACK durumuna göre tekrar dene
                send_packet_with_retries(seq, first_packet, original_packet, server_addr, sock, delay)
                rtt = time.time() - start  # Round-trip time hesapla

                # Adaptif hız kontrolü: RTT yüksekse gecikmeyi artır, düşükse azalt
                if rtt > 0.3:
                    delay = min(max_delay, delay + 0.01)
                    gui_log(f"[Adaptif] Gecikme yüksek ({rtt:.2f}s), hız düşürüldü. delay = {delay:.3f}s")
                elif rtt < 0.1:
                    delay = max(min_delay, delay - 0.005)
                    gui_log(f"[Adaptif] Gecikme düşük ({rtt:.2f}s), hız artırıldı. delay = {delay:.3f}s")

            except Exception as e:
                gui_log(str(e))  # Eğer gönderilemeyen paket varsa, işlemi iptal et
                sock.close()
                return

        # Tüm paketler gönderildikten sonra bitiş mesajı gönder
        sock.sendto(b"END:" + str(total_chunks).encode(), server_addr)
        gui_log("[UDP] Dosya gönderimi tamamlandı.")
        sock.close()

    # -------------------- TCP Transferi --------------------
    else:
        gui_log("[TCP] Bağlantı kuruluyor...")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((SERVER_IP, TCP_PORT))
                gui_log("[TCP] Sunucuya bağlandı.")

                # Kimlik doğrulama için token gönder
                AUTH_TOKEN = b"super_secure_token"
                s.send(struct.pack('!I', len(AUTH_TOKEN))) # Token uzunluğunu gönder
                s.sendall(AUTH_TOKEN) # Tokenı gönder

                # Dosya adını gönder
                file_name_encoded = FILE_NAME.encode()
                s.send(struct.pack('!I', len(file_name_encoded))) # Dosya adı uzunluğunu gönder
                s.sendall(file_name_encoded) # Dosya adını gönder
                gui_log("[TCP] Dosya adı gönderildi.")

                # Şifrelenmiş AES anahtarını gönder
                s.send(struct.pack('!I', len(encrypted_key))) # Şifreli anahtarın uzunluğunu gönder
                s.sendall(encrypted_key) # Şifreli anahtarı gönder
                gui_log("[TCP] Anahtar gönderildi.")

                # Toplam parça sayısını gönder
                s.send(struct.pack('!I', total_chunks)) # Toplam parça sayısını gönder
                gui_log("[TCP] Toplam parça sayısı gönderildi.")

                # Her veri parçasını sırayla gönder
                for seq, corrupted_packet in enumerate(corrupted_packets):
                    hash_digest = corrupted_packet[-32:]
                    encrypted = corrupted_packet[:-32]
                    header = struct.pack('!II', seq, len(encrypted)) + hash_digest # Başlık: sıra, uzunluk, hash
                    s.sendall(header)  # Parça başlığını gönder
                    s.sendall(encrypted)  # Şifreli veri içeriğini gönder
                    gui_log(f"[TCP] Parça gönderildi: {seq+1}/{total_chunks}")
            gui_log("[TCP] Dosya gönderimi tamamlandı.")
        except ConnectionRefusedError:
            gui_log("[TCP] Hata: Bağlantı reddedildi. Sunucunun çalıştığından ve doğru IP/port kullanıldığından emin olun.")
        except Exception as e:
            gui_log(f"[TCP] Bağlantı sırasında hata oluştu: {e}")


def open_gui():
    global log_widget, root, corrupt_packet_count_selected

    root = tk.Tk()
    root.title("Dosya Gönderimi Ayarları")
    root.geometry("900x600")

    # Satır 0: Dosya seçimi
    tk.Label(root, text="Gönderilecek Dosya:").grid(row=0, column=0, padx=10, pady=10, sticky="e")

    file_frame = tk.Frame(root)
    file_frame.grid(row=0, column=1, columnspan=2, sticky="w")

    file_entry = tk.Entry(file_frame, width=60)
    file_entry.pack(side="left", padx=(0, 5))

    tk.Button(file_frame, text="Gözat", command=lambda: file_entry.delete(0, tk.END) or file_entry.insert(0, filedialog.askopenfilename())).pack(side="left")

    # Satır 1: IP girişi
    tk.Label(root, text="Sunucu IP Adresi:").grid(row=1, column=0, padx=10, pady=10, sticky="e")
    ip_entry = tk.Entry(root, width=60)
    ip_entry.grid(row=1, column=1, columnspan=2, padx=5, pady=10, sticky="w")

    # Satır 2: Protokol seçimi
    tk.Label(root, text="Protokol:").grid(row=2, column=0, padx=10, pady=10, sticky="e")
    proto_var = tk.StringVar(value="TCP") # Varsayılan olarak TCP seçili
    proto_frame = tk.Frame(root)
    proto_frame.grid(row=2, column=1, sticky="w", pady=10)
    tk.Radiobutton(proto_frame, text="TCP", variable=proto_var, value="TCP").pack(side="left", padx=10)
    tk.Radiobutton(proto_frame, text="UDP", variable=proto_var, value="UDP").pack(side="left", padx=10)
    tk.Radiobutton(proto_frame, text="HYBRID", variable=proto_var, value="HYBRID").pack(side="left", padx=10)
    
    # Satır 3: Bozuk paket sayısı seçimi (0-10)
    tk.Label(root, text="Bozuk Paket Sayısı (0-10):").grid(row=3, column=0, padx=10, pady=10, sticky="e")
    corrupt_packet_count = tk.IntVar(value=0) # Varsayılan olarak 0 bozuk paket

    def validate_spinbox(new_value):
        if new_value == "":
            return True # Boş girişe izin ver (değer değişince Spinbox otomatik doldurur)
        if new_value.isdigit():
            val = int(new_value)
            return 0 <= val <= 10 # 0 ile 10 arasında değer kontrolü
        return False

    vcmd = (root.register(validate_spinbox), '%P')

    spin_corrupt = tk.Spinbox(root, from_=0, to=10, width=5, textvariable=corrupt_packet_count,
                              validate='key', validatecommand=vcmd)
    spin_corrupt.grid(row=3, column=1, sticky="w")

    # Satır 4: Gönderim Başlat Butonu
    start_button = tk.Button(root, text="Gönderimi Başlat", width=30)
    start_button.grid(row=4, column=0, columnspan=3, pady=15)

    # Satır 5: Log alanı
    log_widget = scrolledtext.ScrolledText(root, width=110, height=25, state='disabled', wrap=tk.WORD)
    log_widget.grid(row=5, column=0, columnspan=3, padx=10, pady=10, sticky="nsew")

    # Buton işlevi
    def on_start():
        global selected_protocol, SERVER_IP, FILE_PATH, corrupt_packet_count_selected

        selected_file = file_entry.get()
        ip = ip_entry.get()
        protocol = proto_var.get()

        if not selected_file:
            messagebox.showerror("Hata", "Geçerli bir dosya seçmelisiniz.")
            return
        if not os.path.isfile(selected_file):
            messagebox.showerror("Hata", "Seçilen dosya bulunamadı veya geçersiz.")
            return
        if not ip:
            messagebox.showerror("Hata", "IP adresi girilmelidir.")
            return

        selected_protocol = protocol
        SERVER_IP = ip
        FILE_PATH = selected_file
        corrupt_packet_count_selected = corrupt_packet_count.get()  # Seçilen değeri al

        start_button.config(state='disabled') # Butonu devre dışı bırak
        start_transfer_thread() # Transferi başlat

    start_button.config(command=on_start)

    # Pencere esneklik ayarları
    root.grid_rowconfigure(5, weight=1)
    root.grid_columnconfigure(1, weight=1)

    root.mainloop()


if __name__ == "__main__":
    open_gui()