/* DES implementation in C
* Author: Ensar Gök.
* License: Apache 2.0
* Medium: https://medium.com/@ensargok/des-fedc78d21045
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define BLOCK_SIZE 64
#define KEY_SIZE 64
#define SUBKEY_SIZE 48
#define ROUNDS 16

#define LOG(...) printf(__VA_ARGS__)
#define LOG_LINE() printf("Line %d reached.\n", __LINE__)

#define POW32 4294967296

int encrypt(char* input, char* key, char* output);
int decrypt(char* input, char* key, char* output);
uint64_t generate_key(char* key_str);

int _des(uint64_t block, uint64_t key, uint64_t* result, int encrypt);

int main(int argc, char** argv)
{
    uint64_t test_data = 0x1122334455667788;
    uint64_t test_key = 0x133457799BBCDFF1;
    uint64_t result;

    _des(test_data, test_key, &result, 1);
    printf("Encrypted: 0x%llu\n", result);

    _des(result, test_key, &result, 0);
    printf("Decrypted: 0x%llu\n", result);

    return 0;
}

int encrypt(char* input, char* key, char* output)
{

}

int decrypt(char* input, char* key, char* output)
{
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

void generate_subkeys(uint64_t key, uint64_t* subkeys[ROUNDS]);

int _des(uint64_t block, uint64_t key, uint64_t* result, int encrypt)
{
    // initial permutation
    uint64_t ip = 0;
    for (int i = 0; i < BLOCK_SIZE; i++)
    {
        ip |= ((block >> (BLOCK_SIZE - IP[i])) & 1) << (BLOCK_SIZE - i - 1);
    }

    // split into left and right
    uint64_t left = ip >> 32;
    uint64_t right = ip & 0xFFFFFFFF;

    // generate subkeys
    uint64_t subkeys[ROUNDS];
    generate_subkeys(key, &subkeys);

    // rounds
    for (int i = 0; i < ROUNDS; i++)
    {
        uint64_t subkey = encrypt ? subkeys[i] : subkeys[ROUNDS - i - 1];

        // expansion permutation
        uint64_t expanded = 0;
        for (int j = 0; j < SUBKEY_SIZE; j++)
        {
            expanded |= ((right >> (SUBKEY_SIZE - E[j])) & 1) << (SUBKEY_SIZE - j - 1);
        }


        // xor with subkey
        expanded ^= subkey;

        // S-boxes
        uint64_t sbox = 0;
        for (int j = 0; j < 8; j++)
        {
            int row = ((expanded >> (6 * j)) & 1) | ((expanded >> (6 * j + 5) & 1)) << 1;
            int col = (expanded >> (6 * j + 1)) & 0xF;
            sbox |= S[j][row][col] << (4 * j);
        }

        // P permutation
        uint64_t p = 0;
        for (int j = 0; j < SUBKEY_SIZE; j++)
        {
            p |= ((sbox >> (SUBKEY_SIZE - P[j])) & 1) << (SUBKEY_SIZE - j - 1);
        }

        // xor with left
        uint64_t temp = right;
        right = left ^ p;
        left = temp;

        if (i < ROUNDS - 1)
        {
            uint64_t temp = left;
            left = right;
            right = temp;
        }
    }

    // combine left and right
    uint64_t combined = (right << 32) | left;

    // final permutation
    uint64_t fp = 0;
    for (int i = 0; i < BLOCK_SIZE; i++)
    {
        fp |= ((combined >> (BLOCK_SIZE - FP[i])) & 1) << (BLOCK_SIZE - i - 1);
    }

    *result = fp;
    return 0;
}

void generate_subkeys(uint64_t key, uint64_t* subkeys[ROUNDS])
{
    // PC1 permutation
    uint64_t pc1 = 0;
    for (int i = 0; i < KEY_SIZE; i++)
    {
        pc1 |= ((key >> (KEY_SIZE - PC1[i])) & 1) << (KEY_SIZE - i - 1);
    }

    // split into left and right
    uint64_t left = pc1 >> 28;
    uint64_t right = pc1 & 0xFFFFFFF;

    for (int i = 0; i < ROUNDS; i++)
    {
        // shift
        left = ((left << 1) & 0xFFFFFFF) | ((left >> 27) & 1);
        right = ((right << 1) & 0xFFFFFFF) | ((right >> 27) & 1);

        // PC2 permutation
        uint64_t pc2 = 0;
        uint64_t combined = (left << 28) | right;
        for (int j = 0; j < SUBKEY_SIZE; j++)
        {
            pc2 |= ((combined >> (SUBKEY_SIZE - PC2[j])) & 1) << (SUBKEY_SIZE - j - 1);
        }

        subkeys[i] = pc2;
    }

    return;    
}