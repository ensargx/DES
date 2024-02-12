/* DES implementation in C
* Author: Ensar Gök.
* License: Apache 2.0
* Medium: https://medium.com/@ensargok/des-fedc78d21045
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>

#define LOG(...) printf(__VA_ARGS__)
#define LOG_LINE() printf("Line %d reached.\n", __LINE__)
#define LOG_BIN_64(x) for (int i = 0; i < 64; i++) { printf("%d", x >> 63 - i & 1); } printf("\n");
#define LOG_BIN_32(x) {for (int i = 0; i < 32; i++) { printf("%d", x >> 31 - i & 1); } printf("\n")};

int encrypt(char* input, char* key);
int decrypt(char* input, char* key);
int _des(uint64_t block, uint64_t key, uint64_t* result, int encrypt);

int main(int argc, char *argv[]) {
    int option;
    char *encrypt_text = NULL;
    char *decrypt_text = NULL;
    char *key = "byEnsarGok";
    char *format = "hex";
    int encrypt_flag = 0;
    int decrypt_flag = 0;

    while ((option = getopt(argc, argv, "e:d:k:f:")) != -1) {
        switch (option) {
            case 'e':
                encrypt_text = optarg;
                encrypt_flag = 1;
                break;
            case 'd':
                decrypt_text = optarg;
                decrypt_flag = 1;
                break;
            case 'k':
                key = optarg;
                break;
            case 'f':
                if (strcmp(optarg, "hex") != 0 && strcmp(optarg, "bin") != 0) {
                    fprintf(stderr, "Error: Format must be either 'hex' or 'bin'.\n");
                    exit(EXIT_FAILURE);
                }
                format = optarg;
                break;
            default:
                fprintf(stderr, "Usage: %s [-e plaintext] [-d ciphertext] [-k key] [-f format]\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if ((encrypt_flag && decrypt_flag) || (!encrypt_flag && !decrypt_flag)) {
        fprintf(stderr, "Error: Must specify either encrypt or decrypt option, and they cannot be used together.\n");
        exit(EXIT_FAILURE);
    }

    printf("Encrypt text: %s\n", encrypt_text);
    printf("Decrypt text: %s\n", decrypt_text);
    printf("Key: %s\n", key);
    printf("Format: %s\n", format);

    if (encrypt_flag)
    {
        encrypt(encrypt_text, key);
    }
    else 
    {
        decrypt(decrypt_text, key);
    }


    return 0;
}

int encrypt(char* input, char* key)
{
    uint64_t block = 0;
    uint64_t key_block = 0;
    uint64_t result = 0;

    // Convert input to 64-bit block
    for (int i = 0; i < 8; i++) {
        block |= (uint64_t)input[i] << (56 - i * 8);
    }

    // Convert key to 64-bit block
    for (int i = 0; i < 8; i++) {
        key_block |= (uint64_t)key[i] << (56 - i * 8);
    }

    // Perform DES
    _des(block, key_block, &result, 1);

    // Print result
    printf("Result: 0x");
    for (int i = 0; i < 8; i++) {
        printf("%x", (result >> (56 - i * 8)) & 0xFF);
    }
    printf("\n");

    return 0;
}

int decrypt(char* input, char* key)
{
    uint64_t block = 0;
    uint64_t key_block = 0;
    uint64_t result = 0;

    // Convert input to 64-bit block
    for (int i = 0; i < 8; i++) {
        block |= (uint64_t)input[i] << (56 - i * 8);
    }

    // Convert key to 64-bit block
    for (int i = 0; i < 8; i++) {
        key_block |= (uint64_t)key[i] << (56 - i * 8);
    }

    // Perform DES
    _des(block, key_block, &result, 0);

    // Print result
    printf("Result: 0x");
    for (int i = 0; i < 8; i++) {
        printf("%x", (result >> (56 - i * 8)) & 0xFF);
    }
    printf("\n");

    return 0;
}

// IP permutation
int IP[] = {58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7};

// FP permutation
int FP[] = {40, 8, 48, 16, 56, 24, 64, 32,
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41, 9, 49, 17, 57, 25};

// PC1 permutation
int PC1[] = {57, 49, 41, 33, 25, 17, 9,
            1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27,
            19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15,
            7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29,
            21, 13, 5, 28, 20, 12, 4};

// PC2 permutation
int PC2[] = {14, 17, 11, 24, 1, 5,
            3, 28, 15, 6, 21, 10,
            23, 19, 12, 4, 26, 8,
            16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55,
            30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53,
            46, 42, 50, 36, 29, 32};

// Expansion permutation
int E[] = {32, 1, 2, 3, 4, 5,
        4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1};

// S-boxes
int S[8][4][16] = {
    {
        {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
        {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
        {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
        {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13},
    },
    {
        {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
        {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
        {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
        {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9},
    },
    {
        {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
        {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
        {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
        {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12},
    },
    {
        {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
        {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
        {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
        {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14},
    },
    {
        {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
        {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
        {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
        {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3},
    },
    {
        {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
        {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
        {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
        {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13},
    },
    {
        {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
        {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
        {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
        {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12},
    },
    {
        {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
        {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
        {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
        {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11},
    }};

// P permutation
int P[] = {16, 7, 20, 21, 29, 12, 28, 17,
        1, 15, 23, 26, 5, 18, 31, 10,
        2, 8, 24, 14, 32, 27, 3, 9,
        19, 13, 30, 6, 22, 11, 4, 25};

int shifts[16] = {
    1, 1, 2, 2, 2, 2, 2, 2,
    1, 2, 2, 2, 2, 2, 2, 1
};


int _des(uint64_t block, uint64_t key, uint64_t* result, int encrypt) {
    uint64_t IP_res = 0;
    uint64_t FP_res = 0;
    uint64_t L = 0;
    uint64_t R = 0;

    // Perform initial permutation
    for (int i = 0; i < 64; i++) {
        IP_res |= ((block >> (64 - IP[i])) & 1) << (63 - i);
    }

    // Split into L and R halves
    L = IP_res >> 32;
    R = IP_res & 0xFFFFFFFF;

    // Generate subkeys
    uint64_t subkeys[16];
    uint64_t permuted_key = 0;
    for (int i = 0; i < 56; i++) {
        permuted_key |= ((key >> (64 - PC1[i])) & 1) << (55 - i);
    }

    // Split into C and D
    uint32_t C = (uint32_t)(permuted_key >> 28);
    uint32_t D = (uint32_t)(permuted_key & 0xFFFFFFF);

    // Generate subkeys
    for (int i = 0; i < 16; i++) {
        // Apply left shift
        int shift_amount = shifts[i];
        C = ((C << shift_amount) | (C >> (28 - shift_amount))) & 0xFFFFFFF;
        D = ((D << shift_amount) | (D >> (28 - shift_amount))) & 0xFFFFFFF;

        // Combine C and D
        uint64_t combined = ((uint64_t)C << 28) | D;

        // Apply PC2 permutation to generate subkey
        subkeys[i] = 0;
        for (int j = 0; j < 48; j++) {
            subkeys[i] |= ((combined >> (56 - PC2[j])) & 1) << (47 - j);
        }
    }

    // Perform Feistel rounds
    for (int round = 0; round < 16; round++) {
        uint64_t temp = R;
        uint64_t expanded_R = 0;
        uint64_t f_result = 0;

        // Expansion permutation
        for (int i = 0; i < 48; i++) {
            expanded_R |= ((R >> (32 - E[i])) & 1) << (47 - i);
        }

        // XOR with subkey
        uint64_t subkey = encrypt ? subkeys[round] : subkeys[15 - round];
        expanded_R ^= subkey;

        // S-box substitution
        for (int i = 0; i < 8; i++) {
            int row = ((expanded_R >> (42 - i * 6)) & 0x01) << 1 | (expanded_R >> (47 - i * 6) & 0x01);
            int col = ((expanded_R >> (43 - i * 6)) & 0x01) << 3 | ((expanded_R >> (44 - i * 6)) & 0x01) << 2 |
                      ((expanded_R >> (45 - i * 6)) & 0x01) << 1 | (expanded_R >> (46 - i * 6) & 0x01);
            uint64_t s_box_value = S[i][row][col];
            f_result |= s_box_value << (32 - 4 * (i + 1));
        }

        // P-box permutation
        uint64_t p_result = 0;
        for (int i = 0; i < 32; i++) {
            p_result |= ((f_result >> (32 - P[i])) & 1) << (31 - i);
        }

        R = L ^ p_result;
        L = temp;
    }

    // Combine R and L
    uint64_t combined = (R << 32) | L;

    // Perform final permutation
    for (int i = 0; i < 64; i++) {
        FP_res |= ((combined >> (64 - FP[i])) & 1) << (63 - i);
    }

    *result = FP_res;
    return 0;
}