import tkinter as tk
from tkinter import ttk, messagebox
import base64, random, math

# ======= HÀM TOÁN HỌC =======
def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def mod_inverse(e, phi):
    def egcd(a, b):
        if a == 0:
            return (b, 0, 1)
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)
    g, x, y = egcd(e, phi)
    return x % phi if g == 1 else None

def is_prime(n, k=10):
    if n < 2:
        return False
    for _ in range(k):
        a = random.randint(2, n - 2)
        if pow(a, n - 1, n) != 1:
            return False
    return True

def generate_prime(bits=16):
    while True:
        num = random.getrandbits(bits)
        num |= 1
        if is_prime(num):
            return num

# ======= TẠO KHÓA RSA =======
def generate_keys():
    try:
        p = int(entry_p.get()) if entry_p.get() else generate_prime(16)
        q = int(entry_q.get()) if entry_q.get() else generate_prime(16)
        e = int(entry_e.get()) if entry_e.get() else 65537

        if not (is_prime(p) and is_prime(q)):
            messagebox.showerror("Lỗi", "p và q phải là số nguyên tố!")
            return

        n = p * q
        phi = (p - 1) * (q - 1)

        if gcd(e, phi) != 1:
            e = 3
            while gcd(e, phi) != 1:
                e += 2

        d = mod_inverse(e, phi)

        entry_p.delete(0, tk.END); entry_p.insert(0, str(p))
        entry_q.delete(0, tk.END); entry_q.insert(0, str(q))
        entry_e.delete(0, tk.END); entry_e.insert(0, str(e))
        entry_n.delete(0, tk.END); entry_n.insert(0, str(n))
        entry_d.delete(0, tk.END); entry_d.insert(0, str(d))

        messagebox.showinfo("Thành công", "✅ Đã tạo cặp khóa RSA thành công!")
    except Exception as ex:
        messagebox.showerror("Lỗi", f"Không thể tạo khóa:\n{ex}")

# ======= MÃ HÓA =======
def encode_text(msg, fmt):
    if fmt == "Text": return msg.encode()
    elif fmt == "Base64": return base64.b64decode(msg)
    elif fmt == "Hex": return bytes.fromhex(msg.replace(" ", ""))
    elif fmt == "Binary":
        bits = msg.replace(" ", "")
        return int(bits, 2).to_bytes((len(bits) + 7)//8, 'big')
    else:
        return msg.encode()

def rsa_encrypt_bytes(data, e, n):
    n_bytes = (n.bit_length() + 7) // 8
    block_size = n_bytes - 1
    result = []
    for i in range(0, len(data), block_size):
        block = data[i:i+block_size]
        block_int = int.from_bytes(block, 'big')
        enc = pow(block_int, e, n)
        result.append(f"{len(block):04x}:{enc:x}")
    return " ".join(result)

def encrypt():
    try:
        msg = entry_message.get().strip()
        if not msg:
            messagebox.showwarning("Cảnh báo", "Vui lòng nhập thông điệp.")
            return

        e = int(entry_e.get())
        n = int(entry_n.get())
        fmt = combo_input_format.get()

        data = encode_text(msg, fmt)
        cipher = rsa_encrypt_bytes(data, e, n)

        entry_cipher.delete(0, tk.END)
        entry_cipher.insert(0, cipher)
        entry_decrypted.delete(0, tk.END)
        messagebox.showinfo("Thành công", "✅ Đã mã hóa thành công! Bạn có thể giải mã ngay.")
    except Exception as ex:
        messagebox.showerror("Lỗi", f"Lỗi khi mã hóa:\n{ex}")

# ======= GIẢI MÃ =======
def decrypt():
    try:
        cipher = entry_cipher.get().strip()
        if not cipher:
            messagebox.showwarning("Cảnh báo", "Vui lòng nhập cipher để giải mã.")
            return

        cipher_fmt = combo_cipher_format.get()
        d = int(entry_d.get())
        n = int(entry_n.get())

        # ---- Giải mã theo từng loại dữ liệu ----
        if cipher_fmt == "Base64":
            cipher_bytes = base64.b64decode(cipher)
            cipher_int = int.from_bytes(cipher_bytes, 'big')
        elif cipher_fmt == "Hex":
            cipher_bytes = bytes.fromhex(cipher.replace(" ", "").replace("\n", ""))
            cipher_int = int.from_bytes(cipher_bytes, 'big')
        elif cipher_fmt == "Binary":
            bits = cipher.replace(" ", "").replace("\n", "")
            cipher_int = int(bits, 2)
        else:  # RSA Format (0005:abcd...)
            plain = rsa_decrypt_hex(cipher, d, n)
            entry_decrypted.delete(0, tk.END)
            entry_decrypted.insert(0, plain)
            messagebox.showinfo("Thành công", "✅ Giải mã thành công!")
            return

        # ---- Thực hiện giải mã RSA ----
        dec_int = pow(cipher_int, d, n)
        dec_bytes = dec_int.to_bytes((dec_int.bit_length() + 7)//8, 'big')

        try:
            plain_text = dec_bytes.decode('utf-8')
        except:
            plain_text = str(dec_bytes)

        entry_decrypted.delete(0, tk.END)
        entry_decrypted.insert(0, plain_text)
        messagebox.showinfo("Thành công", "✅ Giải mã thành công!")

    except Exception as ex:
        messagebox.showerror("Lỗi", f"Lỗi khi giải mã:\n{ex}")

def rsa_decrypt_hex(cipher_text, d, n):
    try:
        result = b""
        blocks = cipher_text.strip().split()
        for blk in blocks:
            if ':' not in blk:
                continue
            orig_len, c_hex = blk.split(':')
            orig_len = int(orig_len, 16)
            c = int(c_hex, 16)
            dec = pow(c, d, n)
            dec_bytes = dec.to_bytes((dec.bit_length() + 7)//8, 'big')
            if len(dec_bytes) < orig_len:
                dec_bytes = b'\x00'*(orig_len - len(dec_bytes)) + dec_bytes
            result += dec_bytes
        return result.decode('utf-8', errors='ignore')
    except Exception as ex:
        return f"[Lỗi giải mã RSA Format: {ex}]"

# ======= GIAO DIỆN =======
root = tk.Tk()
root.title("RSA Encryption/Decryption – Lê Xuân Hoàng")
root.geometry("950x600")
root.configure(bg="#f0f4f7")

tk.Label(root, text="🔐 RSA ENCRYPTION TOOL", font=("Segoe UI", 16, "bold"), bg="#f0f4f7", fg="#1a73e8").pack(pady=10)
frame = tk.Frame(root, bg="#f0f4f7"); frame.pack(padx=20)

# ====== Khóa ======
tk.Label(frame, text="p:", bg="#f0f4f7").grid(row=0, column=0, sticky='e', padx=5, pady=5)
entry_p = tk.Entry(frame, width=20); entry_p.grid(row=0, column=1, padx=5, pady=5)
tk.Label(frame, text="q:", bg="#f0f4f7").grid(row=1, column=0, sticky='e', padx=5, pady=5)
entry_q = tk.Entry(frame, width=20); entry_q.grid(row=1, column=1, padx=5, pady=5)
tk.Label(frame, text="e:", bg="#f0f4f7").grid(row=2, column=0, sticky='e', padx=5, pady=5)
entry_e = tk.Entry(frame, width=20); entry_e.grid(row=2, column=1, padx=5, pady=5)
tk.Button(frame, text="🔑 Tạo khóa", command=generate_keys, bg="#1a73e8", fg="white", width=15).grid(row=3, column=0, columnspan=2, pady=8)

tk.Label(frame, text="n:", bg="#f0f4f7").grid(row=4, column=0, sticky='e', padx=5, pady=5)
entry_n = tk.Entry(frame, width=70); entry_n.grid(row=4, column=1, columnspan=3, padx=5, pady=5)
tk.Label(frame, text="d:", bg="#f0f4f7").grid(row=5, column=0, sticky='e', padx=5, pady=5)
entry_d = tk.Entry(frame, width=70); entry_d.grid(row=5, column=1, columnspan=3, padx=5, pady=5)

ttk.Separator(frame, orient='horizontal').grid(row=6, column=0, columnspan=4, sticky='ew', pady=15)

# ====== Mã hóa / Giải mã ======
tk.Label(frame, text="Thông điệp:", bg="#f0f4f7").grid(row=7, column=0, sticky='e', padx=5, pady=5)
entry_message = tk.Entry(frame, width=70); entry_message.grid(row=7, column=1, columnspan=3, padx=5, pady=5)

tk.Label(frame, text="Format đầu vào:", bg="#f0f4f7").grid(row=8, column=0, sticky='e', padx=5, pady=5)
combo_input_format = ttk.Combobox(frame, values=["Text", "Base64", "Hex", "Binary"], width=17)
combo_input_format.grid(row=8, column=1, padx=5, pady=5); combo_input_format.set("Text")
tk.Button(frame, text="🔒 Mã hóa", command=encrypt, bg="#34a853", fg="white", width=15).grid(row=8, column=2, padx=5)

tk.Label(frame, text="Cipher:", bg="#f0f4f7").grid(row=9, column=0, sticky='e', padx=5, pady=5)
entry_cipher = tk.Entry(frame, width=70); entry_cipher.grid(row=9, column=1, columnspan=3, padx=5, pady=5)

tk.Label(frame, text="Format cipher:", bg="#f0f4f7").grid(row=10, column=0, sticky='e', padx=5, pady=5)
combo_cipher_format = ttk.Combobox(frame, values=["RSA Format", "Base64", "Hex", "Binary"], width=17)
combo_cipher_format.grid(row=10, column=1, padx=5, pady=5); combo_cipher_format.set("RSA Format")
tk.Button(frame, text="🔓 Giải mã", command=decrypt, bg="#ea4335", fg="white", width=15).grid(row=10, column=2, padx=5)

tk.Label(frame, text="Kết quả giải mã:", bg="#f0f4f7").grid(row=11, column=0, sticky='e', padx=5, pady=5)
entry_decrypted = tk.Entry(frame, width=80); entry_decrypted.grid(row=11, column=1, columnspan=3, padx=5, pady=5)

# ====== Hướng dẫn ======
info_text = "💡 Quy trình: (1) Tạo khóa → (2) Nhập thông điệp/cipher → (3) Chọn format → (4) Mã hóa / Giải mã"
tk.Label(root, text=info_text, bg="#f0f4f7", fg="#666", font=("Segoe UI", 9)).pack(pady=5)
tk.Label(root, text="🧩 Hỗ trợ: Text, Base64, Hex, Binary, RSA Format", bg="#f0f4f7", fg="#777", font=("Segoe UI", 8)).pack()

root.mainloop()
