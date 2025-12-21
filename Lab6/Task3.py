import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import math
import os
from collections import Counter

ENGLISH_FREQS = [
    0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015,
    0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749,
    0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758,
    0.00978, 0.02360, 0.00150, 0.01974, 0.00074
]
TARGET_IC = 0.065

class VigenereSilentApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Lab06 - Task 3: Vigenère Cipher")
        self.root.geometry("850x600")
        
        tk.Label(root, text="TASK 3: VIGENÈRE CIPHER", 
                 font=("Arial", 16, "bold"), fg="#004D40").pack(pady=10)

        frame_in = tk.Frame(root)
        frame_in.pack(fill="x", padx=20)
        tk.Button(frame_in, text="Chọn File Ciphertext", command=self.open_file, width=20).pack(side="left")
        self.lbl_path = tk.Label(frame_in, text="...", fg="gray")
        self.lbl_path.pack(side="left", padx=10)

        self.btn_run = tk.Button(root, text="GIẢI MÃ", 
                                 command=self.run_solver, bg="#00695C", fg="white", 
                                 font=("Arial", 12, "bold"), state="disabled")
        self.btn_run.pack(fill="x", padx=20, pady=10)
        
        self.txt_out = scrolledtext.ScrolledText(root, height=18, font=("Consolas", 10))
        self.txt_out.pack(fill="both", expand=True, padx=20, pady=5)
        
        self.btn_save = tk.Button(root, text="Lưu Kết Quả", command=self.save_file, state="disabled")
        self.btn_save.pack(pady=10)

        self.ciphertext_raw = ""
        self.final_key = ""
        self.final_plaintext = ""

    #  CORE MATH FUNCTIONS 
    def calculate_ic(self, text):
        N = len(text)
        if N <= 1: return 0
        counts = Counter(text)
        return sum(n * (n - 1) for n in counts.values()) / (N * (N - 1))

    def get_candidate_lengths(self, clean_text):
        candidates = []
        for k in range(1, 21):
            avg_ic = 0
            valid = 0
            for i in range(k):
                col = clean_text[i::k]
                if len(col) > 1:
                    avg_ic += self.calculate_ic(col)
                    valid += 1
            if valid > 0: avg_ic /= valid
            diff = abs(avg_ic - TARGET_IC)
            candidates.append((k, diff))
        candidates.sort(key=lambda x: x[1])
        return [x[0] for x in candidates[:6]]

    def solve_shift(self, column_text):
        n = len(column_text)
        if n == 0: return 'A'
        counts = Counter(column_text)
        obs = [counts.get(chr(ord('A') + i), 0) / n for i in range(26)]
        
        min_chi = float('inf')
        best_shift = 0
        for s in range(26):
            chi = 0
            for i in range(26):
                idx = (i + s) % 26
                chi += ((obs[idx] - ENGLISH_FREQS[i]) ** 2) / ENGLISH_FREQS[i]
            if chi < min_chi:
                min_chi = chi
                best_shift = s
        return chr(ord('A') + best_shift)

    def decrypt(self, text, key):
        res = []
        key = key.upper()
        k_len = len(key)
        k_idx = 0
        for char in text:
            if char.isalpha():
                shift = ord(key[k_idx % k_len]) - ord('A')
                base = ord('A') if char.isupper() else ord('a')
                dec = chr((ord(char) - base - shift) % 26 + base)
                res.append(dec)
                k_idx += 1
            else:
                res.append(char)
        return "".join(res)

    def calculate_fitness(self, text):
        clean = [c for c in text if c.isalpha()]
        n = len(clean)
        if n == 0: return float('inf')
        counts = Counter(clean)
        obs = [counts.get(chr(ord('A') + i), 0) / n for i in range(26)]
        total = 0
        for i in range(26):
            total += ((obs[i] - ENGLISH_FREQS[i]) ** 2) / ENGLISH_FREQS[i]
        return total

    def select_best_candidate(self, results):
        """Logic chọn lọc ngầm (Divisor Logic) để đảm bảo chọn đúng khóa"""
        results.sort(key=lambda x: x[2]) 
        best_len, best_key, best_score = results[0]
        
        for length, key, score in results:
            if length == best_len: continue
            if best_len % length == 0:
                if score < 0.25: 
                    return length, key, score
        return best_len, best_key, best_score

    def run_solver(self):
        if not self.ciphertext_raw: return
        self.btn_run.config(state="disabled")
        
        self.txt_out.delete(1.0, tk.END)
        self.txt_out.insert(tk.END, "Đang tính toán...\n")
        self.root.update()
        
        clean = "".join([c.upper() for c in self.ciphertext_raw if c.isalpha()])
        
        lengths = self.get_candidate_lengths(clean)
        
        candidates_results = []

        for length in lengths:
            key_chars = []
            for i in range(length):
                col = clean[i::length]
                key_chars.append(self.solve_shift(col))
            key = "".join(key_chars)
            text = self.decrypt(self.ciphertext_raw, key)
            fitness = self.calculate_fitness(text.upper())
            candidates_results.append((length, key, fitness))

        final_len, final_key, final_score = self.select_best_candidate(candidates_results)
        self.final_key = final_key
        self.final_plaintext = self.decrypt(self.ciphertext_raw, final_key)

        self.txt_out.delete(1.0, tk.END) 
        
        self.txt_out.insert(tk.END, f"KHÓA TÌM ĐƯỢC: {self.final_key}\n")
        self.txt_out.insert(tk.END, "-"*60 + "\n")
        self.txt_out.insert(tk.END, self.final_plaintext)
        
        self.btn_run.config(state="normal")
        self.btn_save.config(state="normal")
        messagebox.showinfo("Thành công", f"Đã tìm ra khóa: {self.final_key}")

    def open_file(self):
        fp = filedialog.askopenfilename()
        if fp:
            self.lbl_path.config(text=os.path.basename(fp))
            with open(fp, "r", encoding="utf-8") as f:
                self.ciphertext_raw = f.read()
            self.btn_run.config(state="normal")
            self.txt_out.delete(1.0, tk.END)
            self.txt_out.insert(tk.END, "(Đã tải file. Nhấn Bắt đầu...)\n")

    def save_file(self):
        fp = filedialog.asksaveasfilename(defaultextension=".txt")
        if fp:
            with open(fp, "w", encoding="utf-8") as f:
                f.write(f"{self.final_key}\n")
                f.write(self.final_plaintext)
            messagebox.showinfo("Saved", "Đã lưu.")

if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = VigenereSilentApp(root)
        root.mainloop()
    except: pass