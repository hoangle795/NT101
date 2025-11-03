import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import random, math

# --------------------------
# Miller-Rabin primality test
# --------------------------
def is_prime(n, k=10):
    if n < 2:
        return False
    for p in [2, 3, 5, 7, 11, 13, 17, 19, 23]:
        if n % p == 0:
            return n == p
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

# --------------------------
# Sinh số nguyên tố ngẫu nhiên
# --------------------------
def generate_prime(bits):
    while True:
        num = random.getrandbits(bits) | 1 | (1 << (bits - 1))
        if is_prime(num):
            return num

# --------------------------
# GCD (Euclid)
# --------------------------
def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

# --------------------------
# Modular exponentiation
# --------------------------
def mod_exp(a, x, p):
    result = 1
    a = a % p
    while x > 0:
        if x & 1:  
            result = (result * a) % p
        a = (a * a) % p
        x >>= 1 
    return result

# --------------------------
# Chức năng GUI
# --------------------------
def sinh_nguyento():
    text_output.delete("1.0", tk.END)
    primes = {
        8: generate_prime(8),
        16: generate_prime(16),
        64: generate_prime(64)
    }
    text_output.insert(tk.END, f"🔹 Số nguyên tố 8-bit  : {primes[8]}\n")
    text_output.insert(tk.END, f"🔹 Số nguyên tố 16-bit : {primes[16]}\n")
    text_output.insert(tk.END, f"🔹 Số nguyên tố 64-bit : {primes[64]}\n")

def tim_10_nguyento():
    text_output.delete("1.0", tk.END)
    M = (2 ** 89) - 1
    n = M - 1
    primes = []
    while len(primes) < 10:
        if is_prime(n):
            primes.append(n)
        n -= 1
    text_output.insert(tk.END, f"🔸 10 số nguyên tố lớn nhất nhỏ hơn số nguyên tố Mersenne thứ 10.(2^89 - 1):\n")
    for i, p in enumerate(primes, 1):
        text_output.insert(tk.END, f"{i:2d}. {p}\n")

def kiemtra_nguyento():
    try:
        n = int(entry_check_prime.get())
        M = (2 ** 89) - 1
        if n >= M:
            messagebox.showwarning("Lỗi", "Số phải nhỏ hơn 2^89 - 1!")
            return
        if is_prime(n):
            messagebox.showinfo("Kết quả", f"{n} là SỐ NGUYÊN TỐ.")
        else:
            messagebox.showinfo("Kết quả", f"{n} KHÔNG phải là số nguyên tố.")
    except:
        messagebox.showerror("Lỗi", "Vui lòng nhập số hợp lệ.")

def tinh_gcd():
    try:
        a = int(entry_gcd_a.get())
        b = int(entry_gcd_b.get())
        result = gcd(a, b)
        messagebox.showinfo("Kết quả", f"gcd({a}, {b}) = {result}")
    except:
        messagebox.showerror("Lỗi", "Vui lòng nhập hai số hợp lệ.")

def tinh_modexp():
    try:
        a = int(entry_a.get())
        x = int(entry_x.get())
        p = int(entry_p.get())
        if p <= 0:
            messagebox.showwarning("Lỗi", "p phải > 0")
            return
        result = mod_exp(a, x, p)
        messagebox.showinfo("Kết quả", f"{a}^{x} mod {p} = {result}")
    except:
        messagebox.showerror("Lỗi", "Vui lòng nhập giá trị hợp lệ.")

# --------------------------
# GUI setup
# --------------------------
root = tk.Tk()
root.title("Lý thuyết số - Task 1.1 (Miller-Rabin, GCD, Modular Power)")
root.geometry("720x640")
root.resizable(False, False)

style = ttk.Style()
style.configure("TButton", font=("Arial", 11, "bold"), padding=5)

frame_top = ttk.LabelFrame(root, text="1️ Số nguyên tố", padding=10)
frame_top.pack(fill="x", padx=10, pady=8)

btn_sinh = ttk.Button(frame_top, text="Sinh số nguyên tố 8/16/64 bit", command=sinh_nguyento)
btn_sinh.pack(side="left", padx=5)

btn_mersenne = ttk.Button(frame_top, text="Tìm 10 số nguyên tố < (2^89 - 1)", command=tim_10_nguyento)
btn_mersenne.pack(side="left", padx=5)

frame_check = ttk.LabelFrame(root, text="Kiểm tra số nguyên tố", padding=10)
frame_check.pack(fill="x", padx=10, pady=5)

ttk.Label(frame_check, text="Nhập số n:").pack(side="left")
entry_check_prime = ttk.Entry(frame_check, width=30)
entry_check_prime.pack(side="left", padx=5)
ttk.Button(frame_check, text="Kiểm tra", command=kiemtra_nguyento).pack(side="left", padx=5)

frame_gcd = ttk.LabelFrame(root, text="2️ Ước số chung lớn nhất (GCD - Euclid)", padding=10)
frame_gcd.pack(fill="x", padx=10, pady=5)
ttk.Label(frame_gcd, text="a:").pack(side="left")
entry_gcd_a = ttk.Entry(frame_gcd, width=15)
entry_gcd_a.pack(side="left", padx=5)
ttk.Label(frame_gcd, text="b:").pack(side="left")
entry_gcd_b = ttk.Entry(frame_gcd, width=15)
entry_gcd_b.pack(side="left", padx=5)
ttk.Button(frame_gcd, text="Tính GCD", command=tinh_gcd).pack(side="left", padx=5)

frame_modexp = ttk.LabelFrame(root, text="3️ Lũy thừa theo module a^x mod p", padding=10)
frame_modexp.pack(fill="x", padx=10, pady=5)

ttk.Label(frame_modexp, text="a:").pack(side="left")
entry_a = ttk.Entry(frame_modexp, width=10)
entry_a.pack(side="left", padx=3)
ttk.Label(frame_modexp, text="x:").pack(side="left")
entry_x = ttk.Entry(frame_modexp, width=10)
entry_x.pack(side="left", padx=3)
ttk.Label(frame_modexp, text="p:").pack(side="left")
entry_p = ttk.Entry(frame_modexp, width=10)
entry_p.pack(side="left", padx=3)
ttk.Button(frame_modexp, text="Tính", command=tinh_modexp).pack(side="left", padx=5)

frame_output = ttk.LabelFrame(root, text="🧮 Kết quả hiển thị", padding=10)
frame_output.pack(fill="both", expand=True, padx=10, pady=10)
text_output = scrolledtext.ScrolledText(frame_output, height=15, font=("Consolas", 11))
text_output.pack(fill="both", expand=True)

ttk.Label(root, text="© 2025 Lý thuyết số - Task 1.1 (Miller-Rabin | Euclid | Modular Power)", 
          font=("Arial", 9, "italic")).pack(pady=3)

root.mainloop()
