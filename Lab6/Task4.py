import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import os
import binascii

# =============================================================================
# 1. CÁC BẢNG HẰNG SỐ DES (GIỮ NGUYÊN)
# =============================================================================
IP = [58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,
      57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7]

FP = [40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,
      36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25]

E = [32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,
     16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1]

P = [16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,
     2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25]

PC1 = [57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,
       59,51,43,35,27,19,11,3,60,52,44,36,
       63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,
       61,53,45,37,29,21,13,5,28,20,12,4]

PC2 = [14,17,11,24,1,5,3,28,15,6,21,10,
       23,19,12,4,26,8,16,7,27,20,13,2,
       41,52,31,37,47,55,30,40,51,45,33,48,
       44,49,39,56,34,53,46,42,50,36,29,32]

SHIFT = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]

SBOX = [
[[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
 [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
 [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],
 [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]],
[[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],
 [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
 [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],
 [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]],
[[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],
 [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
 [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],
 [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]],
[[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],
 [13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
 [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],
 [3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]],
[[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],
 [14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
 [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],
 [11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]],
[[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],
 [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
 [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],
 [4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]],
[[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],
 [13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
 [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],
 [6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]],
[[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],
 [1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
 [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],
 [2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]]
]

# =============================================================================
# 2. HÀM HỖ TRỢ & LOGIC DES
# =============================================================================
BLOCK_SIZE = 8

def pad(data):
    pad_len = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([pad_len] * pad_len)

def unpad(data):
    if not data: return data
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 8:
        return data # Padding lỗi, trả về nguyên bản
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        return data
    return data[:-pad_len]

def parse_hex_or_text(input_str):
    """
    Thông minh: Tự động phát hiện nếu chuỗi là Hex thì chuyển sang bytes Hex.
    Nếu không phải Hex hợp lệ, coi là Text UTF-8.
    """
    input_str = input_str.strip()
    try:
        # Nếu độ dài chẵn và chỉ chứa ký tự 0-9, a-f -> Coi là Hex
        # Lưu ý: Key/IV DES thường là hex 16 ký tự (8 byte)
        if len(input_str) % 2 == 0:
            return bytes.fromhex(input_str)
    except:
        pass
    # Mặc định là text
    return input_str.encode('utf-8')

def adjust_key_iv(data_bytes):
    """Chuẩn hóa Key/IV về đúng 8 byte"""
    if len(data_bytes) == 8:
        return data_bytes
    elif len(data_bytes) < 8:
        return data_bytes.ljust(8, b'\x00')
    else:
        return data_bytes[:8]

def permute(block, table, size):
    return ''.join(block[i-1] for i in table)

def xor(a, b):
    return ''.join('0' if i == j else '1' for i, j in zip(a, b))

def shift_left(k, n):
    return k[n:] + k[:n]

def generate_keys(key_bits):
    key_bits = permute(key_bits, PC1, 56)
    C, D = key_bits[:28], key_bits[28:]
    keys = []
    for i in SHIFT:
        C = shift_left(C, i)
        D = shift_left(D, i)
        keys.append(permute(C+D, PC2, 48))
    return keys

def sbox_sub(s):
    out = ''
    for i in range(8):
        block = s[i*6:(i+1)*6]
        row = int(block[0]+block[5], 2)
        col = int(block[1:5], 2)
        out += f'{SBOX[i][row][col]:04b}'
    return out

def feistel(R, K):
    exp = permute(R, E, 48)
    x = xor(exp, K)
    s = sbox_sub(x)
    return permute(s, P, 32)

def des_block(block, keys, decrypt=False):
    block = permute(block, IP, 64)
    L, R = block[:32], block[32:]
    if decrypt:
        keys = keys[::-1]
    for k in keys:
        temp = R
        R = xor(L, feistel(R, k))
        L = temp
    return permute(R + L, FP, 64)

def bytes_to_bits(b): return ''.join(f'{i:08b}' for i in b)
def bits_to_bytes(s): return int(s, 2).to_bytes(len(s)//8, 'big')

# --- Logic Mã hóa / Giải mã ---
def des_encrypt_logic(data, key, mode, iv):
    data = pad(data)
    keys = generate_keys(bytes_to_bits(key))
    out = b''
    prev = iv

    for i in range(0, len(data), 8):
        block = data[i:i+8]
        bits = bytes_to_bits(block)

        if mode == "ECB":
            enc = des_block(bits, keys)
            enc_bytes = bits_to_bytes(enc)
            
        elif mode == "CBC":
            xor_block = bytes_to_bits(bytes(a ^ b for a, b in zip(block, prev)))
            enc = des_block(xor_block, keys)
            enc_bytes = bits_to_bytes(enc)
            prev = enc_bytes 

        elif mode == "CFB":
            enc_prev = des_block(bytes_to_bits(prev), keys) 
            enc_prev_bytes = bits_to_bytes(enc_prev)
            enc_bytes = bytes(a ^ b for a, b in zip(block, enc_prev_bytes))
            prev = enc_bytes 

        elif mode == "OFB":
            enc_prev = des_block(bytes_to_bits(prev), keys)
            enc_prev_bytes = bits_to_bytes(enc_prev)
            enc_bytes = bytes(a ^ b for a, b in zip(block, enc_prev_bytes))
            prev = enc_prev_bytes 

        out += enc_bytes
    return out

def des_decrypt_logic(data, key, mode, iv):
    keys = generate_keys(bytes_to_bits(key))
    out = b''
    prev = iv

    for i in range(0, len(data), 8):
        block = data[i:i+8]
        bits = bytes_to_bits(block)

        if mode == "ECB":
            dec = des_block(bits, keys, decrypt=True)
            dec_bytes = bits_to_bytes(dec)

        elif mode == "CBC":
            dec = des_block(bits, keys, decrypt=True)
            dec_bytes_raw = bits_to_bytes(dec)
            dec_bytes = bytes(a ^ b for a, b in zip(dec_bytes_raw, prev))
            prev = block 

        elif mode == "CFB":
            enc_prev = des_block(bytes_to_bits(prev), keys)
            enc_prev_bytes = bits_to_bytes(enc_prev)
            dec_bytes = bytes(a ^ b for a, b in zip(block, enc_prev_bytes))
            prev = block 

        elif mode == "OFB":
            enc_prev = des_block(bytes_to_bits(prev), keys)
            enc_prev_bytes = bits_to_bytes(enc_prev)
            dec_bytes = bytes(a ^ b for a, b in zip(block, enc_prev_bytes))
            prev = enc_prev_bytes

        out += dec_bytes
    return unpad(out)

# =============================================================================
# 3. GIAO DIỆN (GUI)
# =============================================================================
class DESApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Lab06 - Task 4: DES (Robust)")
        self.root.geometry("700x650")
        
        # --- TITLE ---
        tk.Label(root, text="TASK 4: DES ENCRYPTION/DECRYPTION", 
                 font=("Arial", 14, "bold"), fg="#D32F2F").pack(pady=10)

        # --- CONFIG FRAME (KEY, IV, MODE) ---
        frame_conf = tk.Frame(root)
        frame_conf.pack(fill="x", padx=20)
        
        tk.Label(frame_conf, text="Key (Hex/Text):").grid(row=0, column=0, sticky="w")
        self.ent_key = tk.Entry(frame_conf, width=25)
        self.ent_key.grid(row=0, column=1, padx=5)
        
        tk.Label(frame_conf, text="IV (Hex/Text):").grid(row=0, column=2, sticky="w")
        self.ent_iv = tk.Entry(frame_conf, width=25)
        self.ent_iv.grid(row=0, column=3, padx=5)
        
        tk.Label(frame_conf, text="Mode:").grid(row=0, column=4, sticky="w")
        self.mode_var = tk.StringVar(value="CBC")
        tk.OptionMenu(frame_conf, self.mode_var, "ECB", "CBC", "CFB", "OFB").grid(row=0, column=5)

        # --- INPUT SECTION ---
        tk.Label(root, text="Input (Text / Hex Ciphertext):", font=("Arial", 10, "bold")).pack(anchor="w", padx=20, pady=(10,0))
        self.txt_input = scrolledtext.ScrolledText(root, height=8)
        self.txt_input.pack(fill="x", padx=20, pady=5)

        # --- BUTTONS FRAME ---
        frame_btn = tk.Frame(root)
        frame_btn.pack(pady=10)
        tk.Button(frame_btn, text="ENCRYPT (Mã hóa)", command=self.do_encrypt, 
                  bg="#4CAF50", fg="white", font=("Arial", 9, "bold")).pack(side="left", padx=10)
        tk.Button(frame_btn, text="DECRYPT (Giải mã)", command=self.do_decrypt, 
                  bg="#2196F3", fg="white", font=("Arial", 9, "bold")).pack(side="left", padx=10)

        # --- OUTPUT SECTION ---
        tk.Label(root, text="Output:", font=("Arial", 10, "bold")).pack(anchor="w", padx=20)
        self.txt_output = scrolledtext.ScrolledText(root, height=8)
        self.txt_output.pack(fill="x", padx=20, pady=5)

    def get_params(self):
        raw_key_str = self.ent_key.get().strip()
        raw_iv_str = self.ent_iv.get().strip()
        mode = self.mode_var.get()
        
        if not raw_key_str:
            messagebox.showerror("Lỗi", "Vui lòng nhập Key!")
            return None
        
        # --- FIX QUAN TRỌNG: Tự động chuyển Hex sang Bytes ---
        key = adjust_key_iv(parse_hex_or_text(raw_key_str))
        
        # Xử lý IV
        iv = b'\x00' * 8
        if mode != "ECB":
            if not raw_iv_str:
                # Nếu encrypt mà thiếu IV thì sẽ tự sinh sau
                iv = b'' 
            else:
                iv = adjust_key_iv(parse_hex_or_text(raw_iv_str))
                
        return key, iv, mode, raw_iv_str

    def do_encrypt(self):
        res = self.get_params()
        if not res: return
        key, iv, mode, raw_iv_str = res
        
        plaintext = self.txt_input.get("1.0", tk.END).strip().encode('utf-8')
        if not plaintext:
            messagebox.showerror("Lỗi", "Vui lòng nhập nội dung cần mã hóa!")
            return

        # Nếu Mode cần IV mà người dùng chưa nhập -> Tự sinh
        if mode != "ECB" and len(iv) == 0:
            iv = os.urandom(8)
            self.ent_iv.delete(0, tk.END)
            self.ent_iv.insert(0, binascii.hexlify(iv).decode())

        try:
            encrypted_bytes = des_encrypt_logic(plaintext, key, mode, iv)
            hex_out = binascii.hexlify(encrypted_bytes).decode()
            self.txt_output.delete(1.0, tk.END)
            self.txt_output.insert(tk.END, hex_out)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def do_decrypt(self):
        res = self.get_params()
        if not res: return
        key, iv, mode, raw_iv_str = res
        
        # Lấy Input Hex, xóa sạch khoảng trắng và xuống dòng
        hex_in = self.txt_input.get("1.0", tk.END).replace('\n', '').replace(' ', '').strip()
        if not hex_in:
            messagebox.showerror("Lỗi", "Vui lòng nhập Ciphertext (Hex)!")
            return
            
        try:
            ciphertext = binascii.unhexlify(hex_in)
        except binascii.Error:
            messagebox.showerror("Lỗi", "Input phải là chuỗi Hex hợp lệ!")
            return

        if mode != "ECB" and len(iv) != 8:
            messagebox.showerror("Lỗi", f"Chế độ {mode} yêu cầu IV 8 byte (16 ký tự Hex)!")
            return

        try:
            decrypted_data = des_decrypt_logic(ciphertext, key, mode, iv)
            # Thử decode UTF-8, nếu không được thì in Hex
            try:
                plaintext = decrypted_data.decode('utf-8')
            except UnicodeDecodeError:
                plaintext = "Cảnh báo: Giải mã xong nhưng không phải UTF-8 (Sai Key/IV?).\nRaw: " + str(decrypted_data)
            
            self.txt_output.delete(1.0, tk.END)
            self.txt_output.insert(tk.END, plaintext)
        except Exception as e:
            messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    root = tk.Tk()
    app = DESApp(root)
    root.mainloop()