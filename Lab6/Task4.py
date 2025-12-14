import tkinter as tk
from tkinter import messagebox, scrolledtext
import random
import binascii

# =============================================================================
# CÁC BẢNG HẰNG SỐ CHUẨN CỦA DES (DES CONSTANTS)
# =============================================================================

# Bảng hoán vị khởi tạo (Initial Permutation - IP)
IP = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]

# Bảng hoán vị kết thúc (Final Permutation - IP-1)
FP = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
      38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
      36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
      34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25]

# Bảng mở rộng (Expansion Function E)
E = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
     8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]

# Bảng hoán vị P (Permutation P)
P = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]

# 8 Hộp thay thế (Substitution Boxes - S-Boxes)
S_BOX = [
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],

    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],

    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
     [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
     [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
     [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],

    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
     [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
     [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
     [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],

    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
     [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
     [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
     [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],

    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
     [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
     [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
     [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],

    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
     [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],

    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
     [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
     [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
     [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
]

# Bảng nén khóa (Permuted Choice)
PC1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2,
       59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39,
       31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37,
       29, 21, 13, 5, 28, 20, 12, 4]

PC2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4,
       26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40,
       51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]

# Số bit dịch vòng trái tại mỗi vòng lặp (16 vòng)
SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

# --- 2. LỚP XỬ LÝ DES (IMPLEMENTATION) ---
class DESCipher:
    def __init__(self, key_bytes):
        self.key_bits = self.bytes_to_bits(key_bytes)
        self.subkeys = self.generate_subkeys()

    def bytes_to_bits(self, b_data):
        bits = []
        for byte in b_data:
            for i in range(7, -1, -1):
                bits.append((byte >> i) & 1)
        return bits

    def bits_to_bytes(self, bits):
        bytes_list = []
        for i in range(0, len(bits), 8):
            byte = 0
            for j in range(8):
                byte = (byte << 1) | bits[i + j]
            bytes_list.append(byte)
        return bytes(bytes_list)

    def permute(self, block, table):
        return [block[x - 1] for x in table]

    def xor(self, bits1, bits2):
        return [x ^ y for x, y in zip(bits1, bits2)]

    def generate_subkeys(self):
        temp_key = self.permute(self.key_bits, PC1)
        c, d = temp_key[:28], temp_key[28:]
        subkeys = []
        
        for shift in SHIFTS:
            c = c[shift:] + c[:shift]
            d = d[shift:] + d[:shift]
            cd = c + d
            subkeys.append(self.permute(cd, PC2))
        return subkeys

    def feistel_function(self, r_block, subkey):
        expanded = self.permute(r_block, E)
        xored = self.xor(expanded, subkey)
        output = []
        for i in range(8):
            row = (xored[i*6] << 1) | xored[i*6 + 5]
            col = (xored[i*6 + 1] << 3) | (xored[i*6 + 2] << 2) | (xored[i*6 + 3] << 1) | xored[i*6 + 4]
            val = S_BOX[i][row][col]
            for j in range(3, -1, -1):
                output.append((val >> j) & 1)
        return self.permute(output, P)

    def process_block(self, block_bits, mode='encrypt'):
        block = self.permute(block_bits, IP)
        left, right = block[:32], block[32:]
        
        keys = self.subkeys if mode == 'encrypt' else self.subkeys[::-1]
        
        for i in range(16):
            temp = right
            f_result = self.feistel_function(right, keys[i])
            right = self.xor(left, f_result)
            left = temp
            
        combined = right + left
        return self.permute(combined, FP)

    def encrypt_block(self, block_bytes):
        bits = self.bytes_to_bits(block_bytes)
        enc_bits = self.process_block(bits, 'encrypt')
        return self.bits_to_bytes(enc_bits)

    def decrypt_block(self, block_bytes):
        bits = self.bytes_to_bits(block_bytes)
        dec_bits = self.process_block(bits, 'decrypt')
        return self.bits_to_bytes(dec_bits)

# --- 3. CÁC HÀM HỖ TRỢ ---

def pad_pkcs7(data):
    pad_len = 8 - (len(data) % 8)
    return data + bytes([pad_len] * pad_len)

def unpad_pkcs7(data):
    pad_len = data[-1]
    return data[:-pad_len]

class DESApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Lab06 - Task 4: DES")
        self.root.geometry("700x650")
        
        tk.Label(root, text="TASK 4: DES ENCRYPTION/DECRYPTION", 
                 font=("Arial", 12, "bold"), fg="#D32F2F").pack(pady=10)

        frame_conf = tk.Frame(root)
        frame_conf.pack(fill="x", padx=20)
        
        tk.Label(frame_conf, text="Key (8 chars):").grid(row=0, column=0, sticky="w")
        self.ent_key = tk.Entry(frame_conf, width=20)
        self.ent_key.grid(row=0, column=1, padx=5)
        
        tk.Label(frame_conf, text="IV (8 chars, optional):").grid(row=0, column=2, sticky="w")
        self.ent_iv = tk.Entry(frame_conf, width=20)
        self.ent_iv.grid(row=0, column=3, padx=5)
        
        tk.Label(frame_conf, text="Mode:").grid(row=0, column=4, sticky="w")
        self.mode_var = tk.StringVar(value="ECB")
        tk.OptionMenu(frame_conf, self.mode_var, "ECB", "CBC").grid(row=0, column=5)

        tk.Label(root, text="Input (Plaintext / Hex Ciphertext):", font=("Arial", 10, "bold")).pack(anchor="w", padx=20, pady=(10,0))
        self.txt_input = scrolledtext.ScrolledText(root, height=8)
        self.txt_input.pack(fill="x", padx=20, pady=5)

        frame_btn = tk.Frame(root)
        frame_btn.pack(pady=10)
        tk.Button(frame_btn, text="ENCRYPT (Mã hóa)", command=self.do_encrypt, bg="#4CAF50", fg="white").pack(side="left", padx=10)
        tk.Button(frame_btn, text="DECRYPT (Giải mã)", command=self.do_decrypt, bg="#2196F3", fg="white").pack(side="left", padx=10)

        tk.Label(root, text="Output:", font=("Arial", 10, "bold")).pack(anchor="w", padx=20)
        self.txt_output = scrolledtext.ScrolledText(root, height=8)
        self.txt_output.pack(fill="x", padx=20, pady=5)

    def get_params(self):
        key = self.ent_key.get().encode('utf-8')
        iv = self.ent_iv.get().encode('utf-8')
        mode = self.mode_var.get()
        
        if len(key) != 8:
            messagebox.showerror("Lỗi", "Key phải đúng 8 ký tự (64 bit)!")
            return None
        return key, iv, mode

    def do_encrypt(self):
        params = self.get_params()
        if not params: return
        key, iv, mode = params
        
        plaintext = self.txt_input.get("1.0", tk.END).strip().encode('utf-8')
        des = DESCipher(key)
        padded = pad_pkcs7(plaintext)
        
        ciphertext = b""
        
        if mode == "ECB":
            for i in range(0, len(padded), 8):
                block = padded[i:i+8]
                ciphertext += des.encrypt_block(block)
        elif mode == "CBC":
            if len(iv) != 8:
                iv = bytes([random.randint(0, 255) for _ in range(8)]) 
                self.ent_iv.delete(0, tk.END)
                # Hiển thị IV (Latin-1) để người dùng biết mà lưu lại nếu cần
                self.ent_iv.insert(0, iv.decode('latin-1', 'ignore'))
            
            curr_vec = iv
            for i in range(0, len(padded), 8):
                block = padded[i:i+8]
                xored = bytes([b ^ v for b, v in zip(block, curr_vec)])
                enc_block = des.encrypt_block(xored)
                ciphertext += enc_block
                curr_vec = enc_block
        
        # CHỈ HIỂN THỊ CIPHERTEXT (HEX)
        hex_out = binascii.hexlify(ciphertext).decode()
        self.txt_output.delete(1.0, tk.END)
        self.txt_output.insert(tk.END, hex_out)

    def do_decrypt(self):
        params = self.get_params()
        if not params: return
        key, iv, mode = params
        
        try:
            # Lấy Input là chuỗi Hex thuần
            hex_in = self.txt_input.get("1.0", tk.END).strip()
            ciphertext = binascii.unhexlify(hex_in)
        except:
            messagebox.showerror("Lỗi", "Input phải là chuỗi Hex hợp lệ!")
            return

        des = DESCipher(key)
        decrypted = b""
        
        if mode == "ECB":
            for i in range(0, len(ciphertext), 8):
                block = ciphertext[i:i+8]
                decrypted += des.decrypt_block(block)
        elif mode == "CBC":
            if len(iv) != 8:
                messagebox.showerror("Lỗi", "Mode CBC cần IV 8 byte! Hãy kiểm tra ô 'IV'.")
                return
            prev_block = iv
            for i in range(0, len(ciphertext), 8):
                curr_block = ciphertext[i:i+8]
                dec_block = des.decrypt_block(curr_block)
                plain_block = bytes([b ^ p for b, p in zip(dec_block, prev_block)])
                decrypted += plain_block
                prev_block = curr_block

        try:
            plaintext = unpad_pkcs7(decrypted).decode('utf-8')
            self.txt_output.delete(1.0, tk.END)
            self.txt_output.insert(tk.END, plaintext)
        except:
            messagebox.showerror("Lỗi", "Giải mã thất bại (Padding hoặc Key sai)!")

if __name__ == "__main__":
    root = tk.Tk()
    app = DESApp(root)
    root.mainloop()