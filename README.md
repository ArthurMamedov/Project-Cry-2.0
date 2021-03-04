# Project-Cry-2.0
Project Cry 2.0 (Improved version of Project Cry)

This is a simple file cryptor created for **demonstration** purposes.

##Supported algorithms:
- AES
- GOST28147-89
- BLOWFISH
- ANUBIS

##Supported encryption modes:
- ECB
- CBC
- CFB
- OFB
- CTR

##How to use
Give to the program the following parameters:
- encrypt/decrypt/help (encrypt, decrypt file or pring help message)
- specify the file(s) to encrypt/decrypt
- specify the encryption algorithm (listed above)
- specify the encryption mode (listed above)
- specify the key to encrypt with

###Example
Cry.exe encrypt file.png aes ecb 1234567887654321
(remark: key length may be different depending on the algorithm)
