import string


def shift_char(c, k):
    if c.isupper():
        return chr((ord(c) - ord('A') + k) % 26 + ord('A'))
    elif c.islower():
        return chr((ord(c) - ord('a') + k) % 26 + ord('a'))
    else:
        return c

def encrypt(plaintext, key):
    return ''.join(shift_char(c, key) for c in plaintext)

def decrypt(ciphertext, key):
    return ''.join(shift_char(c, -key) for c in ciphertext)

def brute_force(ciphertext):
    print("Brute-force results for all possible keys:")
    for key in range(26):
        candidate = decrypt(ciphertext, key)
        print(f"Key {key:2}: {candidate}\n")

def main():
    print("Caesar Cipher Application")
    print("1. Encrypt")
    print("2. Decrypt")
    print("3. Brute-force Decryption")
    choice = input("Choose an option (1/2/3): ").strip()

    if choice == "1":
        plaintext = input("Enter plaintext: ")
        key = int(input("Enter key (0-25): "))
        ciphertext = encrypt(plaintext, key)
        print(f"Ciphertext: {ciphertext}")
    elif choice == "2":
        ciphertext = input("Enter ciphertext: ")
        key = int(input("Enter key (0-25): "))
        plaintext = decrypt(ciphertext, key)
        print(f"Plaintext: {plaintext}")
    elif choice == "3":
        ciphertext = input("Enter ciphertext for brute-force: ")
        brute_force(ciphertext)
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()