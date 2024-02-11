
import sys
sys.path.append('../')
sys.path.append('.')

from des import DES

"""
Plaintext: 0123456789ABCDEF
Key: 133457799BBCDFF1
Expected Ciphertext: 85E813540F0AB405

Plaintext: 0123456789ABCDEF
Key: 0000000000000000
Expected Ciphertext: 8CA64DE9C1B123A7

Plaintext: FEDCBA9876543210
Key: 133457799BBCDFF1
Expected Ciphertext: 79953A9E5063A26A

Plaintext: FEDCBA9876543210
Key: 0000000000000000
Expected Ciphertext: 7A5BBCB84DAA24EE
"""

def main():
    des = DES()

    key_bin = hex2binlist("133457799BBCDFF1")

    des.initial_key = key_bin
    des.key = des.generate_subkeys()
    print(binlist2hex(des.key[0]))





def hex2binlist(hex_str):
    key_bin = bin(int(hex_str, 16))[2:]
    while len(key_bin) < 64:
        key_bin = '0' + key_bin
    bin_list = []
    for i in key_bin:
        bin_list.append(int(i))
    return bin_list

def binlist2hex(bin_list):
    # pad with 0s
    while len(bin_list) < 64:
        bin_list.insert(0, 0)
    bin_str = ''.join(str(i) for i in bin_list)
    hex_str = hex(int(bin_str, 2))[2:]
    return "0x" + hex_str.upper()
if __name__ == "__main__":
    main()