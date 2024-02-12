# DES
Welcome to the DES (Data Encryption Standard) project! This project showcases my personal implementation of DES in both Python and C languages. While this implementation may not be suitable for handling sensitive data, it serves as a fantastic learning opportunity and a testament to my exploration of encryption concepts.

## What is DES?
Discover the fundamentals of DES and its significance in the realm of cryptography. Gain insights into how this algorithm has shaped the landscape of modern encryption techniques.

Read the details from [Medium: DES](https://medium.com/@ensargok/des-fedc78d21045)

## Usage
You can use the program to *encode/decode* data.

You can use python version without any dependencies. Or you can compile with any C compiler and use it.

## Example
```bash
$ python3 des.py -e "Hello World!"
Plaintext: Hello World!
Ciphertext: 0x42b4d8a6efa875e2f95b269f4038abbc
$ python3 des.py -d 0x42b4d8a6efa875e2f95b269f4038abbc
Ciphertext: 0x42b4d8a6efa875e2f95b269f4038abbc
Plaintext: Hello World!
```

### Parameters
**-k / --key** Provieded key will be hashed and the hash will be the key for the encryption/decryption. Default key is "byEnsarGok".
Output will change with diffrent keys and to decrypt data, you will need the same key to get the right answer.

**-e / --encrypt** To encrypt data.

**-d / --decrypt** To decrypt data.

**-f / --format** \[hex | bin] data format to use.

## Future Features

I'm committed to enhancing this DES project over time. Here are some features I plan to add in future updates:

- **Expanded Functionality**: I aim to expand the capabilities of this DES implementation, potentially adding support for different modes of operation and key lengths.

- **Improved Performance**: Continuously optimizing the codebase to improve performance and efficiency, ensuring smooth execution even for large datasets.

- **Python DES Tester**: In addition to the implementation, I plan to develop a Python-based DES tester. This tool will enable users to validate and test their own DES implementations against reference results, fostering a deeper understanding of DES concepts and aiding in the development of new implementations.

Stay tuned for these exciting updates, and join me in exploring the ever-evolving landscape of cryptography and encryption!
