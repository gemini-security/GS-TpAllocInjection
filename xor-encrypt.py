import sys
import os
import re

def xor_cipher(data, key):
    key = [ord(c) for c in key]
    return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

def main():
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <filename.h>")
        sys.exit(1)

    input_file = sys.argv[1]
    key = "S3cur3P4ssw0rd!2025" # You can randomize this further

    if not os.path.exists(input_file):
        print(f"Error: {input_file} not found.")
        return

    with open(input_file, 'r') as f:
        content = f.read()

    # Extract hex bytes using regex
    hex_pattern = r'\\x([0-9a-fA-F]{2})'
    matches = re.findall(hex_pattern, content)
    if not matches:
        print("No shellcode found in the file.")
        return

    original_bytes = bytes([int(x, 16) for x in matches])
    encrypted_bytes = xor_cipher(original_bytes, key)

    # Format for C++ header
    formatted_hex = ""
    for i, b in enumerate(encrypted_bytes):
        formatted_hex += f"\\x{b:02x}"
        if (i + 1) % 14 == 0:
            formatted_hex += "\"\n\""

    output_content = f'unsigned char buf[] = \n"{formatted_hex}";'

    with open("payload_enc.h", "w") as f:
        f.write(output_content)

    print(f"[+] Encrypted file saved as: payload_enc.h")
    print(f"[+] XOR Key: {key}")
    print(f"[+] Payload Length: {len(encrypted_bytes)} bytes")

if __name__ == "__main__":
    main()
