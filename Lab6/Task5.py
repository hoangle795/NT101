import tkinter as tk
from tkinter import messagebox, scrolledtext
import random
import binascii
import string

# =============================================================================
# CẤU HÌNH AES (GIỮ NGUYÊN)
# =============================================================================
S_BOX = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

INV_S_BOX = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)

RCON = (
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
    0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
    0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
)

def xtime(a):
    return (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)

def gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1: p ^= a
        a = xtime(a)
        b >>= 1
    return p

# =============================================================================
# LỚP XỬ LÝ AES (GIỮ NGUYÊN)
# =============================================================================
class AESCipher:
    def __init__(self, key):
        self.key = key
        k_len = len(key)
        
        if k_len == 16:
            self.n_rounds = 10
            self.nk = 4
        elif k_len == 24:
            self.n_rounds = 12
            self.nk = 6
        elif k_len == 32:
            self.n_rounds = 14
            self.nk = 8
        else:
            raise ValueError(f"Độ dài khóa ({k_len} bytes) không hợp lệ! AES chỉ hỗ trợ 16, 24 hoặc 32 bytes.")
            
        self.round_keys = self._key_expansion(key)

    def _key_expansion(self, master_key):
        key_columns = [list(master_key[i:i+4]) for i in range(0, len(master_key), 4)]
        limit = 4 * (self.n_rounds + 1)
        
        for i in range(self.nk, limit):
            word = list(key_columns[-1])
            
            if i % self.nk == 0:
                word.append(word.pop(0)) # RotWord
                word = [S_BOX[b] for b in word] # SubWord
                word[0] ^= RCON[i // self.nk]
            
            elif self.nk > 6 and i % self.nk == 4:
                word = [S_BOX[b] for b in word]

            prev_nk_word = key_columns[-self.nk]
            word = [w ^ k for w, k in zip(word, prev_nk_word)]
            key_columns.append(word)
            
        return key_columns

    def _sub_bytes(self, state, inv=False):
        box = INV_S_BOX if inv else S_BOX
        for r in range(4):
            for c in range(4):
                state[r][c] = box[state[r][c]]
        return state

    def _shift_rows(self, state, inv=False):
        count = 1
        for r in range(1, 4):
            if inv: state[r] = state[r][-count:] + state[r][:-count]
            else:   state[r] = state[r][count:] + state[r][:count]
            count += 1
        return state

    def _mix_columns(self, state, inv=False):
        for i in range(4):
            c = [state[r][i] for r in range(4)]
            if inv:
                state[0][i] = gmul(c[0], 14) ^ gmul(c[1], 11) ^ gmul(c[2], 13) ^ gmul(c[3], 9)
                state[1][i] = gmul(c[0], 9) ^ gmul(c[1], 14) ^ gmul(c[2], 11) ^ gmul(c[3], 13)
                state[2][i] = gmul(c[0], 13) ^ gmul(c[1], 9) ^ gmul(c[2], 14) ^ gmul(c[3], 11)
                state[3][i] = gmul(c[0], 11) ^ gmul(c[1], 13) ^ gmul(c[2], 9) ^ gmul(c[3], 14)
            else:
                state[0][i] = gmul(c[0], 2) ^ gmul(c[1], 3) ^ c[2] ^ c[3]
                state[1][i] = c[0] ^ gmul(c[1], 2) ^ gmul(c[2], 3) ^ c[3]
                state[2][i] = c[0] ^ c[1] ^ gmul(c[2], 2) ^ gmul(c[3], 3)
                state[3][i] = gmul(c[0], 3) ^ c[1] ^ c[2] ^ gmul(c[3], 2)
        return state

    def _add_round_key(self, state, round_key):
        for c in range(4):
            for r in range(4):
                state[r][c] ^= round_key[c][r]
        return state

    def encrypt_block(self, plaintext):
        state = [[plaintext[r + 4*c] for c in range(4)] for r in range(4)]
        state = self._add_round_key(state, self.round_keys[:4])
        
        for i in range(1, self.n_rounds):
            state = self._sub_bytes(state)
            state = self._shift_rows(state)
            state = self._mix_columns(state)
            state = self._add_round_key(state, self.round_keys[i*4 : (i+1)*4])
            
        state = self._sub_bytes(state)
        state = self._shift_rows(state)
        state = self._add_round_key(state, self.round_keys[self.n_rounds*4:])
        
        output = []
        for c in range(4):
            for r in range(4):
                output.append(state[r][c])
        return bytes(output)

    def decrypt_block(self, ciphertext):
        state = [[ciphertext[r + 4*c] for c in range(4)] for r in range(4)]
        state = self._add_round_key(state, self.round_keys[self.n_rounds*4:])
        
        for i in range(self.n_rounds - 1, 0, -1):
            state = self._shift_rows(state, inv=True)
            state = self._sub_bytes(state, inv=True)
            state = self._add_round_key(state, self.round_keys[i*4 : (i+1)*4])
            state = self._mix_columns(state, inv=True)
            
        state = self._shift_rows(state, inv=True)
        state = self._sub_bytes(state, inv=True)
        state = self._add_round_key(state, self.round_keys[:4])
        
        output = []
        for c in range(4):
            for r in range(4):
                output.append(state[r][c])
        return bytes(output)

# =============================================================================
# CÁC HÀM HỖ TRỢ (FIXED)
# =============================================================================

def pad_pkcs7(data):
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)

def unpad_pkcs7(data):
    if not data: return data
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        return data # Trả về raw nếu padding sai
    # Kiểm tra tính toàn vẹn của padding
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        return data 
    return data[:-pad_len]

def smart_parse_input(text):
    """
    Tự động nhận diện Hex hay Text.
    - Nếu là chuỗi Hex hợp lệ có độ dài khớp với Key (32/48/64 chars) hoặc IV (32 chars) -> Convert sang bytes.
    - Ngược lại -> Encode UTF-8.
    """
    text = text.strip()
    # Kiểm tra Hex
    if all(c in string.hexdigits for c in text):
        # AES-128 (16 byte -> 32 hex), AES-192 (24->48), AES-256 (32->64), IV (16->32)
        if len(text) in [32, 48, 64]:
            try:
                return bytes.fromhex(text)
            except: pass
    
    # Mặc định là Text
    return text.encode('utf-8')

# =============================================================================
# GIAO DIỆN APP (FIXED LOGIC)
# =============================================================================
class AESApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Lab06 - Task 5: AES (Robust)")
        self.root.geometry("750x650")
        
        tk.Label(root, text="AES ENCRYPTION/DECRYPTION", 
                 font=("Arial", 12, "bold"), fg="#1565C0").pack(pady=10)
        
        frame_cf = tk.Frame(root)
        frame_cf.pack(fill="x", padx=20)
        
        tk.Label(frame_cf, text="Key (Hex/Text):").grid(row=0, column=0, sticky="w")
        self.ent_key = tk.Entry(frame_cf, width=22)
        self.ent_key.grid(row=0, column=1, padx=5)
        
        tk.Label(frame_cf, text="IV (Hex/Text):").grid(row=0, column=2, sticky="w")
        self.ent_iv = tk.Entry(frame_cf, width=20)
        self.ent_iv.grid(row=0, column=3, padx=5)
        
        tk.Label(frame_cf, text="Mode:").grid(row=0, column=4)
        self.mode_var = tk.StringVar(value="ECB")
        tk.OptionMenu(frame_cf, self.mode_var, "ECB", "CBC").grid(row=0, column=5)

        tk.Label(root, text="Input (Plaintext / Hex Ciphertext):", font=("Arial", 10, "bold")).pack(anchor="w", padx=20, pady=(10,0))
        self.txt_in = scrolledtext.ScrolledText(root, height=8)
        self.txt_in.pack(fill="x", padx=20, pady=5)

        frame_btn = tk.Frame(root)
        frame_btn.pack(pady=10)
        tk.Button(frame_btn, text="ENCRYPT", command=self.do_encrypt, bg="#4CAF50", fg="white", width=15).pack(side="left", padx=10)
        tk.Button(frame_btn, text="DECRYPT", command=self.do_decrypt, bg="#2196F3", fg="white", width=15).pack(side="left", padx=10)

        tk.Label(root, text="Output Result (Hex):", font=("Arial", 10, "bold")).pack(anchor="w", padx=20)
        self.txt_out = scrolledtext.ScrolledText(root, height=8)
        self.txt_out.pack(fill="x", padx=20, pady=5)

    def get_params(self):
        raw_key = self.ent_key.get()
        raw_iv = self.ent_iv.get()
        mode = self.mode_var.get()
        
        # --- FIX 1: Dùng smart parsing cho Key/IV ---
        key = smart_parse_input(raw_key)
        iv = smart_parse_input(raw_iv) if raw_iv else b''
        
        if len(key) not in [16, 24, 32]:
            messagebox.showerror("Lỗi độ dài Key", 
                                 f"Key hiện tại dài {len(key)} bytes.\n"
                                 "Vui lòng nhập đúng 16 (AES-128), 24 (AES-192) hoặc 32 (AES-256) bytes.\n"
                                 "(Gợi ý: Nếu nhập Hex 32 ký tự -> sẽ là 16 bytes)")
            return None
        return key, iv, mode

    def do_encrypt(self):
        p = self.get_params()
        if not p: return
        key, iv, mode = p
        
        try:
            aes = AESCipher(key)
            plaintext = self.txt_in.get("1.0", tk.END).strip().encode('utf-8')
            padded = pad_pkcs7(plaintext)
            ciphertext = b""
            
            if mode == "ECB":
                for i in range(0, len(padded), 16):
                    block = padded[i:i+16]
                    ciphertext += aes.encrypt_block(block)
            
            elif mode == "CBC":
                if len(iv) != 16:
                    # Tự sinh IV nếu thiếu hoặc độ dài sai (khi người dùng nhập bừa)
                    iv = bytes([random.randint(0, 255) for _ in range(16)])
                    self.ent_iv.delete(0, tk.END)
                    self.ent_iv.insert(0, binascii.hexlify(iv).decode())
                
                curr_vec = iv
                for i in range(0, len(padded), 16):
                    block = padded[i:i+16]
                    xored = bytes([b ^ v for b, v in zip(block, curr_vec)])
                    enc = aes.encrypt_block(xored)
                    ciphertext += enc
                    curr_vec = enc
            
            hex_out = binascii.hexlify(ciphertext).decode()
            self.txt_out.delete(1.0, tk.END)
            self.txt_out.insert(tk.END, hex_out)
                
        except Exception as e:
            messagebox.showerror("Lỗi Mã hóa", str(e))

    def do_decrypt(self):
        p = self.get_params()
        if not p: return
        key, iv, mode = p
        
        try:
            # --- FIX 2: Làm sạch input (xóa \n, space) ---
            inp_str = self.txt_in.get("1.0", tk.END).replace('\n', '').replace(' ', '').strip()
            ciphertext = binascii.unhexlify(inp_str)
                
            aes = AESCipher(key)
            decrypted = b""
            
            if mode == "ECB":
                for i in range(0, len(ciphertext), 16):
                    block = ciphertext[i:i+16]
                    if len(block) == 16: # Chỉ xử lý block đủ
                        decrypted += aes.decrypt_block(block)
                    
            elif mode == "CBC":
                if len(iv) != 16:
                    messagebox.showerror("Lỗi", "Mode CBC cần IV 16 byte (32 hex chars)!")
                    return
                prev = iv
                for i in range(0, len(ciphertext), 16):
                    curr = ciphertext[i:i+16]
                    if len(curr) == 16:
                        dec = aes.decrypt_block(curr)
                        plain = bytes([b ^ v for b, v in zip(dec, prev)])
                        decrypted += plain
                        prev = curr
            
            # --- FIX 3: Xử lý hiển thị an toàn ---
            final_data = unpad_pkcs7(decrypted)
            self.txt_out.delete(1.0, tk.END)
            
            try:
                plaintext = final_data.decode('utf-8')
                self.txt_out.insert(tk.END, plaintext)
            except UnicodeDecodeError:
                # Nếu decode lỗi (do sai Key), hiện Hex để người dùng biết
                msg = "Cảnh báo: Không thể decode UTF-8 (Có thể sai Key/IV).\nRaw Hex:\n"
                msg += binascii.hexlify(final_data).decode()
                self.txt_out.insert(tk.END, msg)
            
        except Exception as e:
            messagebox.showerror("Lỗi Giải mã", f"Lỗi: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = AESApp(root)
    root.mainloop()