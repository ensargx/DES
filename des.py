#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# DES implementation in Python
# Author: Ensar Gök
# License: Apache 2.0
# Medium: https://medium.com/@ensargok/des-fedc78d21045

from typing import Literal
import argparse

class DES:
    def __init__(self, key_str: str = "byEnsarGok"):
        self.initial_key = self.generate_key(key_str)
        self.key = self.generate_subkeys()

        # Expansion table
        self._expansion_table = [
            32, 1, 2, 3, 4, 5,
            4, 5, 6, 7, 8, 9,
            8, 9, 10, 11, 12, 13,
            12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21,
            20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29,
            28, 29, 30, 31, 32, 1
        ]

        # Permutation table
        self._permutation_table = [
            16, 7, 20, 21, 29, 12, 28, 17,
            1, 15, 23, 26, 5, 18, 31, 10,
            2, 8, 24, 14, 32, 27, 3, 9,
            19, 13, 30, 6, 22, 11, 4, 25
        ]

    def encrypt(self, plaintext: str, out_format: Literal['hex', 'bin'] = 'hex'):
        # convert the data to binary
        plaintext = ''.join(format(ord(i), '08b') for i in plaintext)

        # convert the data to a list of integers
        plaintext = [int(i) for i in plaintext]

        # Split the plaintext into 64-bit blocks
        data_list = []
        for i in range(0, len(plaintext), 64):
            if len(plaintext[i:i + 64]) < 64:
                plaintext += [0] * (64 - len(plaintext[i:i + 64]))
            data_list.append(plaintext[i:i + 64])

        # Encrypt the plaintext using the key
        data = []
        for block in data_list:
            data += self._des(block)

        # convert the data to hex
        if out_format == 'hex':
            # Convert binary to bytes objext
            data = ''.join(str(bit) for bit in data)
            data = int(data, 2).to_bytes((len(data) + 7) // 8, byteorder='big')
            data = '0x' + ''.join([format(byte, '02x') for byte in data])
        elif out_format == 'bin':
            data = ''.join(map(str, data))
        return data

    def decrypt(self, ciphertext, out_format: Literal['hex', 'bin'] = 'hex'):
        # convert the data to binary
        if out_format == 'hex':
            ciphertext = int(ciphertext, 16).to_bytes((len(ciphertext) - 2) // 2, byteorder='big')
            ciphertext = ''.join(format(i, '08b') for i in ciphertext)
        elif out_format == 'bin':
            ciphertext = ''.join(ciphertext)

        # convert the data to a list of integers
        ciphertext = [int(i) for i in ciphertext]

        # Split the ciphertext into 64-bit blocks
        data_list = []
        for i in range(0, len(ciphertext), 64):
            data_list.append(ciphertext[i:i + 64])

        # Decrypt the ciphertext using the key
        data = []
        for block in data_list:
            data += self._des(block, encrypt=False)

        # convert the data to a string
        data = ''.join([chr(int(''.join(map(str, data[i:i + 8])), 2)) for i in range(0, len(data), 8)])

        return data

    def _des(self, data, encrypt=True):
        # Initial permutation
        data = self._initial_permutation(data)
        
        # 16 rounds of encryption
        for i in range(16):
            # Split the data into left and right parts
            left, right = data[:32], data[32:]

            # Expand the right part
            right_expanded = self._permute(right, self._expansion_table)

            # XOR the right part with the key
            if encrypt:
                right_xor = self._xor(right_expanded, self.key[i])
            else:
                right_xor = self._xor(right_expanded, self.key[15 - i])

            # S-boxes
            right_sboxed = self._s_boxes(right_xor)

            # Permutation
            right_permuted = self._permute(right_sboxed, self._permutation_table)

            # XOR the left part with the right part (after permutation)
            left = self._xor(left, right_permuted)

            # Swap the left and right parts
            data = right + left

        # Swap the left and right parts
        data = data[32:] + data[:32]

        # Final permutation
        data = self._final_permutation(data)
        return data

    def _xor(self, data, key):
        # XOR the data with the key
        return [data[i] ^ key[i] for i in range(len(data))]
    
    def _s_boxes(self, data):
        # S-boxes
        s_boxes = [
            # S1
            [
                [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
                [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
                [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
                [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
            ],
            # S2
            [
                [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
                [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
                [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
                [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
            ],
            # S3
            [
                [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
                [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
                [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
                [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
            ],
            # S4
            [
                [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
                [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
                [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
                [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
            ],
            # S5
            [
                [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
                [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
                [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
                [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
            ],
            # S6
            [
                [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
                [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
                [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
                [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
            ],
            # S7
            [
                [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
                [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
                [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
                [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
            ],
            # S8
            [
                [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
                [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
                [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
                [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
            ]
        ]

        # Split the data into 6-bit parts
        parts = [data[i:i + 6] for i in range(0, len(data), 6)]

        # S-box lookup
        sboxed = []
        for i, part in enumerate(parts):
            row = int(str(part[0]) + str(part[5]), 2)
            col = int(''.join(str(x) for x in part[1:][:-1]), 2)
            sboxed += [int(x) for x in format(s_boxes[i][row][col], '04b')]
    
        return sboxed
    
    def _initial_permutation(self, data):
        # Initial permutation table
        initial_permutation_table = [
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7
        ]

        # Permute the data using the initial permutation table
        return self._permute(data, initial_permutation_table)

    def _final_permutation(self, data):
        # Final permutation table
        final_permutation_table = [
            40, 8, 48, 16, 56, 24, 64, 32,
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41, 9, 49, 17, 57, 25
        ]

        # Permute the data using the final permutation table
        return self._permute(data, final_permutation_table)

    def _permute(self, data, table):
        # Permute the data using the given table
        permuted_data = [None] * len(table)
        for i, index in enumerate(table):
            permuted_data[i] = data[index - 1]
        return permuted_data

    def _left_shift(self, data):
        # Left shift the data by 1
        return data[1:] + [data[0]]

    def generate_key(self, key: str):
        # Compute hash value for key generation
        hash_value = 0
        for i in key:
            hash_value = (hash_value * 31 + ord(i)) & 0xFFFFFFFFFFFFFFFF
        hash_value = hash_value % 2**32

        # LCG for random number generation
        def lcg():
            nonlocal hash_value
            hash_value = (1103515245 * hash_value + 12345) & 0x7fffffff
            return hash_value

        # Generate 64-bit key using LCG
        return [(lcg() >> i) & 1 for i in range(64)]

    def generate_subkeys(self):
        # Generate 16 48-bit subkeys using the given 56-bit key
        subkeys = []
        PC1 = [
            57, 49, 41, 33, 25, 17, 9,
            1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27,
            19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15,
            7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29,
            21, 13, 5, 28, 20, 12, 4
        ]

        # Permute the key using the PC1 table
        initial_key = self._permute(self.initial_key, PC1)

        # Split the key into left and right parts
        left, right = initial_key[:28], initial_key[28:]

        # Generate 16 subkeys
        for i in range(16):
            # Left shift the left and right parts
            new_left = self._left_shift(left)
            new_right = self._left_shift(right)

            # Combine the left and right parts
            combined = new_left + new_right

            # Permute the combined parts using the PC2 table
            subkey = self._permute(combined, [
                14, 17, 11, 24, 1, 5, 3, 28,
                15, 6, 21, 10, 23, 19, 12, 4,
                26, 8, 16, 7, 27, 20, 13, 2,
                41, 52, 31, 37, 47, 55, 30, 40,
                51, 45, 33, 48, 44, 49, 39, 56,
                34, 53, 46, 42, 50, 36, 29, 32
            ])

            # Add the subkey to the list of subkeys
            subkeys.append(subkey)

            # Update the left and right parts
            left, right = new_left, new_right

        return subkeys


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='DES encryption and decryption')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-e', '--encrypt', type=str, help='Plaintext to encrypt')
    group.add_argument('-d', '--decrypt', type=str, help='Ciphertext to decrypt')
    parser.add_argument('-k', '--key', type=str, help='Key for encryption and decryption. Default is "byEnsarGok"', default="byEnsarGok")
    parser.add_argument('-f', '--format', type=str, help='Format of the input and output', default="hex", choices=['hex', 'bin'])

    args = parser.parse_args()

    des = DES(key_str=args.key)
    if args.encrypt:
        print(f"Plaintext: {args.encrypt}")
        ciphertext = des.encrypt(args.encrypt, out_format=args.format)
        print(f"Ciphertext: {ciphertext}")

    if args.decrypt:
        print(f"Ciphertext: {args.decrypt}")
        try:
            plaintext = des.decrypt(args.decrypt, out_format=args.format)
        except (IndexError, OverflowError, ValueError):
            print("Invalid ciphertext")
            exit(1)
        print(f"Plaintext: {plaintext}")
