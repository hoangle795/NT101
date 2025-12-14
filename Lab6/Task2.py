import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import random
import math
import os
import re
import collections
import string

ENGLISH_FREQ_ORDER = "etaoinshrdlcumwfgypbvkjxqz"

BIGRAM_LOGS = {
    'th': -1.52, 'he': -1.28, 'in': -1.63, 'er': -1.70, 'an': -1.78, 're': -1.85,
    'nd': -2.01, 'at': -2.12, 'on': -2.23, 'nt': -2.31, 'ha': -2.33, 'es': -2.45,
    'st': -2.49, 'en': -2.55, 'ed': -2.63, 'to': -2.64, 'it': -2.66, 'ou': -2.71,
    'ea': -2.76, 'hi': -2.79, 'is': -2.83, 'or': -2.85, 'ti': -2.85, 'as': -2.85,
    'te': -2.88, 'et': -2.93, 'ng': -2.96, 'of': -2.99, 'al': -3.06, 'de': -3.07,
    'se': -3.08, 'le': -3.10, 'sa': -3.13, 'si': -3.17, 'ar': -3.18, 've': -3.20,
    'ra': -3.22, 'ld': -3.24, 'ur': -3.25
}

COMMON_WORDS = {
    "the", "of", "and", "to", "in", "a", "is", "that", "for", "it", "as", "was", "with",
    "be", "by", "on", "not", "he", "i", "this", "are", "or", "his", "from", "at", "which",
    "but", "have", "an", "had", "they", "you", "were", "their", "one", "all", "we", "can",
    "computer", "system", "security", "network", "information", "technology", "data", 
    "software", "hardware", "internet", "university", "cyber", "protection", "digital",
    "process", "application", "science", "engineering", "algorithm", "encryption"
}

class Task2CleanApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Lab06 - Task 2: Mono-alphabetic substitution cipher")
        self.root.geometry("850x650") 
        
        tk.Label(root, text="TASK 2:  Mono-alphabetic substitution cipher", 
                 font=("Arial", 14, "bold"), fg="#2E7D32").pack(pady=10)

        frame_in = tk.Frame(root)
        frame_in.pack(fill="x", padx=20)
        tk.Button(frame_in, text="Chọn File Ciphertext", command=self.open_file, width=20).pack(side="left")
        self.lbl_path = tk.Label(frame_in, text="...", fg="gray")
        self.lbl_path.pack(side="left", padx=10)

        self.btn_run = tk.Button(root, text="Giải mã", 
                                 command=self.run_process, bg="#43A047", fg="white", 
                                 font=("Arial", 12, "bold"), state="disabled")
        self.btn_run.pack(fill="x", padx=20, pady=10)
        

        self.txt_out = scrolledtext.ScrolledText(root, height=20, font=("Consolas", 10))
        self.txt_out.pack(fill="both", expand=True, padx=20, pady=5)
        
        self.btn_save = tk.Button(root, text="Lưu Kết Quả", command=self.save_file, state="disabled")
        self.btn_save.pack(pady=10)

        self.ciphertext = ""
        self.best_map = {}
        self.best_text = ""
        self.best_score = -float('inf')

    # 1. TẠO KHÓA -
    def get_freq_seed(self, text):
        chars = [c for c in text if c.isalpha()]
        if not chars: return self.get_random_map()
        
        counter = collections.Counter(chars)
        sorted_cipher = [p[0] for p in counter.most_common()]
        
        mapping = {}
        used_plain = set()
        
        for i, char in enumerate(sorted_cipher):
            if i < len(ENGLISH_FREQ_ORDER):
                target = ENGLISH_FREQ_ORDER[i]
                mapping[char] = target
                used_plain.add(target)
        
        all_chars = list(string.ascii_lowercase)
        rem_cipher = [c for c in all_chars if c not in mapping]
        rem_plain = [c for c in all_chars if c not in used_plain]
        random.shuffle(rem_plain)
        
        for c, p in zip(rem_cipher, rem_plain):
            mapping[c] = p
        return mapping

    def get_random_map(self):
        a = list(string.ascii_lowercase)
        b = list(string.ascii_lowercase)
        random.shuffle(b)
        return dict(zip(a, b))

    #  2. HÀM DECRYPT 
    def decrypt(self, text, mapping):
        full_map = mapping.copy()
        full_map.update({k.upper(): v.upper() for k, v in mapping.items()})
        table = str.maketrans(full_map)
        return text.translate(table)

    # 3. HÀM TÍNH ĐIỂM 
    def calculate_score(self, text):
        text_clean = "".join([c for c in text if c.isalpha()]) 
        if len(text_clean) < 2: return -999999.0
        
        score = 0
        for i in range(len(text_clean)-1):
            bg = text_clean[i:i+2]
            score += BIGRAM_LOGS.get(bg, -15.0)
            
        words = re.findall(r'\b[a-z]{2,}\b', text)
        for w in words:
            if w in COMMON_WORDS:
                score += 50.0 
        return score

    #  4. SIMULATED ANNEALING 
    def simulated_annealing(self, cipher_lower, start_map=None):
        if start_map:
            curr_map = start_map.copy()
        else:
            curr_map = self.get_freq_seed(cipher_lower)
            
        curr_text = self.decrypt(cipher_lower, curr_map)
        curr_score = self.calculate_score(curr_text)
        
        best_local_map = curr_map.copy()
        best_local_score = curr_score
        
        chars = list(curr_map.keys())
        temp = 30.0
        step = 0.5
        
        iter_count = 0
        
        while temp > 0:
            for _ in range(1000): 
                new_map = curr_map.copy()
                c1, c2 = random.sample(chars, 2)
                new_map[c1], new_map[c2] = new_map[c2], new_map[c1]
                
                new_text = self.decrypt(cipher_lower, new_map)
                new_score = self.calculate_score(new_text)
                
                diff = new_score - curr_score
                
                if diff > 0 or random.random() < math.exp(diff / temp):
                    curr_map = new_map
                    curr_score = new_score
                    if curr_score > best_local_score:
                        best_local_score = curr_score
                        best_local_map = curr_map.copy()
            
            temp -= step
            iter_count += 1
            
            if iter_count % 5 == 0:
                self.root.update() 
            
        return best_local_map, best_local_score

    def run_process(self):
        if not self.ciphertext: return
        self.btn_run.config(state="disabled")
        
        cipher_lower = self.ciphertext.lower()
        self.best_score = -float('inf')
        
        try:
            TOTAL_ROUNDS = 3
            for i in range(TOTAL_ROUNDS):
                self.root.update()
                
                if i == 0:
                    seed = self.get_freq_seed(cipher_lower)
                else:
                    seed = self.get_random_map()
                
                l_map, l_score = self.simulated_annealing(cipher_lower, start_map=seed)
                
                if l_score > self.best_score:
                    self.best_score = l_score
                    self.best_map = l_map
                    self.best_text = self.decrypt(self.ciphertext, l_map)
                    
                    self.txt_out.delete(1.0, tk.END)
                    self.txt_out.insert(tk.END, self.best_text)
                    self.root.update()

            self.btn_save.config(state="normal")
            messagebox.showinfo("Thành công", "Đã tìm ra kết quả tối ưu!")
            
        except Exception as e:
            messagebox.showerror("Lỗi", str(e))
        finally:
            self.btn_run.config(state="normal")

    def open_file(self):
        fp = filedialog.askopenfilename()
        if fp:
            self.lbl_path.config(text=os.path.basename(fp))
            with open(fp, "r", encoding="utf-8") as f:
                self.ciphertext = f.read()
            self.btn_run.config(state="normal")
            self.txt_out.delete(1.0, tk.END)
            self.txt_out.insert(tk.END, self.ciphertext[:500] + "...\n(Sẵn sàng)")

    def save_file(self):
        fp = filedialog.asksaveasfilename(defaultextension=".txt")
        if fp:
            with open(fp, "w", encoding="utf-8") as f:
                f.write(f"Score: {self.best_score:.2f}\n")
                sorted_map = sorted(self.best_map.items())
                map_str = ", ".join([f"{k}->{v}" for k,v in sorted_map])
                f.write(f"Mapping: {map_str}\n")
                f.write(self.best_text)
            messagebox.showinfo("Saved", "Đã lưu file đúng định dạng.")

if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = Task2CleanApp(root)
        root.mainloop()
    except: pass