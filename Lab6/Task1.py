import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import os

class CaesarCipherApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Lab06 - Task 1: Caesar Cipher")
        self.root.geometry("600x500")
        
        #  GIAO DIỆN (GUI)
        
        self.label_title = tk.Label(root, text="TASK 1: CAESAR CIPHER", font=("Arial", 14, "bold"))
        self.label_title.pack(pady=10)

        self.frame_input = tk.Frame(root)
        self.frame_input.pack(pady=5, fill="x", padx=10)
        
        self.btn_open = tk.Button(self.frame_input, text="Chọn File Ciphertext (Input)", command=self.open_file)
        self.btn_open.pack(side="left", padx=5)
        
        self.lbl_input_path = tk.Label(self.frame_input, text="Chưa chọn file...", fg="gray")
        self.lbl_input_path.pack(side="left", padx=5)

        self.btn_crack = tk.Button(root, text="TÌM KHÓA & GIẢI MÃ", command=self.crack_cipher, bg="#4CAF50", fg="white", font=("Arial", 10, "bold"))
        self.btn_crack.pack(pady=10)

        self.lbl_result = tk.Label(root, text="Kết quả:", font=("Arial", 10, "bold"))
        self.lbl_result.pack(anchor="w", padx=10)

        self.txt_output = scrolledtext.ScrolledText(root, height=15)
        self.txt_output.pack(fill="both", expand=True, padx=10, pady=5)

        self.btn_save = tk.Button(root, text="Lưu Plaintext ra File (Output)", command=self.save_file, state="disabled")
        self.btn_save.pack(pady=10)

        self.ciphertext_content = ""
        self.best_key = -1
        self.best_plaintext = ""

    #  LOGIC XỬ LÝ (ALGORITHM)

    def decrypt_caesar(self, text, key):
        """
        Hàm giải mã thủ công theo yêu cầu[cite: 35, 130].
        Chỉ dịch ký tự A-Z, a-z.
        """
        result = []
        for char in text:
            if 'A' <= char <= 'Z':
                # Dịch ngược lại k bước: (char - k)
                # Công thức giải mã: D(x) = (x - k) mod 26
                decoded_char = chr((ord(char) - 65 - key) % 26 + 65)
                result.append(decoded_char)
            elif 'a' <= char <= 'z':
                decoded_char = chr((ord(char) - 97 - key) % 26 + 97)
                result.append(decoded_char)
            else:
                # Giữ nguyên khoảng trắng và dấu câu 
                result.append(char)
        return "".join(result)

    def calculate_score(self, text):
        """
        Hàm tính điểm để xác định plaintext tiếng Anh chuẩn.
        Dựa trên tần suất xuất hiện của các từ phổ biến trong tiếng Anh.
        """
        common_words = ["THE", "BE", "TO", "OF", "AND", "A", "IN", "THAT", "HAVE", "IS", "IT", "FOR",
                         "NOT", "ON", "WITH", "HE", "AS", "YOU", "DO", "AT"]
        
        score = 0
        text_upper = text.upper()
        
        for word in common_words:
            score += text_upper.count(f" {word} ") 
        return score

    def open_file(self):
        filepath = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if filepath:
            self.lbl_input_path.config(text=os.path.basename(filepath), fg="black")
            try:
                # Đọc file định dạng UTF-8 [cite: 19]
                with open(filepath, "r", encoding="utf-8") as f:
                    self.ciphertext_content = f.read()
                messagebox.showinfo("Thành công", "Đã tải nội dung ciphertext.")
            except Exception as e:
                messagebox.showerror("Lỗi", f"Không đọc được file: {e}")

    def crack_cipher(self):
        if not self.ciphertext_content:
            messagebox.showwarning("Cảnh báo", "Vui lòng chọn file ciphertext trước!")
            return

        best_score = -1
        self.best_key = 0
        self.best_plaintext = ""

        # Thử tất cả khóa khả dĩ từ 0 đến 25 
        # Vì đề bài yêu cầu tìm "plaintext duy nhất", ta dùng heuristic chấm điểm
        for key in range(26):
            temp_text = self.decrypt_caesar(self.ciphertext_content, key)
            # Chỉ lấy 2000 ký tự đầu để chấm điểm cho nhanh
            score = self.calculate_score(temp_text[:2000]) 
            
            if score > best_score:
                best_score = score
                self.best_key = key
                self.best_plaintext = temp_text

        display_text = f"KEY FOUND: {self.best_key}\n"
        display_text += "-" * 30 + "\n"
        display_text += self.best_plaintext
        
        self.txt_output.delete(1.0, tk.END)
        self.txt_output.insert(tk.END, display_text)
        
        self.btn_save.config(state="normal")
        messagebox.showinfo("Hoàn tất", f"Đã tìm thấy khóa khả thi nhất: {self.best_key}")

    def save_file(self):
        if not self.best_plaintext:
            return
            
        filepath = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
        if filepath:
            try:
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(f"{self.best_key}\n")
                    f.write(self.best_plaintext)
                messagebox.showinfo("Thành công", "Đã lưu file plaintext.")
            except Exception as e:
                messagebox.showerror("Lỗi", f"Không ghi được file: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = CaesarCipherApp(root)
    root.mainloop()