import tkinter as tk
from tkinter import messagebox
import pywifi
from pywifi import const
import time
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

def encrypt_password(password, key):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(password.encode())
    return base64.b64encode(nonce + ciphertext).decode('utf-8')

def decrypt_password(enc_password, key):
    enc_password = base64.b64decode(enc_password)
    nonce = enc_password[:16]
    ciphertext = enc_password[16:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt(ciphertext).decode('utf-8')

def connect_wifi():
    ssid = ssid_entry.get()
    password = password_entry.get()

    if not ssid or not password:
        messagebox.showwarning("Uyarı", "Lütfen hem SSID hem de şifreyi girin!")
        return

    key = b'ThisIsA16ByteKey' 

    encrypted_password = encrypt_password(password, key)
    print(f"Şifrelenmiş Şifre: {encrypted_password}")

    decrypted_password = decrypt_password(encrypted_password, key)
    print(f"Çözülmüş Şifre: {decrypted_password}")

    wifi = pywifi.PyWiFi()
    iface = wifi.interfaces()[0] 

    iface.disconnect() 
    time.sleep(1)

    profile = pywifi.Profile()
    profile.ssid = ssid  # Wi-Fi adı
    profile.auth = const.AUTH_ALG_OPEN  # Açık ağ mı, şifreleme gerekli mi
    profile.akm.append(const.AKM_TYPE_WPA2PSK)  # WPA2 PSK kullan
    profile.cipher = const.CIPHER_TYPE_CCMP  # WPA2 için şifreleme türü CCMP
    profile.key = decrypted_password  # Wi-Fi şifresi (çözülmüş hali)

    iface.remove_all_network_profiles()  # Eski profilleri temizleme
    tmp_profile = iface.add_network_profile(profile)  # Yeni profili ekleme

    iface.connect(tmp_profile)
    time.sleep(10)

    if iface.status() == const.IFACE_CONNECTED:
        messagebox.showinfo("Başarılı", f"{ssid} ağına başarıyla bağlandı!")
    else:
        messagebox.showerror("Hata", f"{ssid} ağına bağlanılamadı.")

# Tkinter arayüzü oluşturma
root = tk.Tk()
root.title("Wi-Fi Bağlantı Arayüzü")

# SSID etiketi ve girişi
ssid_label = tk.Label(root, text="SSID:")
ssid_label.grid(row=0, column=0, padx=10, pady=10)
ssid_entry = tk.Entry(root)
ssid_entry.grid(row=0, column=1, padx=10, pady=10)

# Şifre etiketi ve girişi
password_label = tk.Label(root, text="Wi-Fi Şifresi:")
password_label.grid(row=1, column=0, padx=10, pady=10)
password_entry = tk.Entry(root, show="*")
password_entry.grid(row=1, column=1, padx=10, pady=10)

# Bağlanma butonu
connect_button = tk.Button(root, text="Bağlan", command=connect_wifi)
connect_button.grid(row=2, columnspan=2, pady=10)

# Arayüzü başlatma
root.mainloop()
