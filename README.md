# JCrypt
This is a simple CLI text/file encrypter made in Java that supports XOR and AES-256 (with salt).

## Compatibility
It was written in Java using the jdk-21 so any machine with jdk-21 (or later) installed should be able to run it fine.
You can also recompile it using an older version of the sdk such as jdk-17

## Usage

```console
foo@bar:~$ java -jar JCrypt.jar

<====== JCrypt - By Slyvred ======>
XOR and AES-256 encryption tool

1. Xor text
2. Xor file
3. Encrypt file (AES-256)
4. Decrypt file (AES-256)
5. Encrypt folder (AES-256)
6. Decrypt folder (AES-256)
7. Exit

Select an option: 
```

## How does it work ?
### AES Encryption

- We generate an AES-256 key with the password submitted by the user and a randomly generated 16 bytes salt
- We store the salt inside of the encrypted data at a position calculated by dividing the length (in bytes) of the encrypted data + 16 by the length of the password.

### AES Decryption

- We calculate the AES-256 key with the password submitted by the user and the salt stored in the file
- We recover the salt position in the file by dividing the length of the file (in bytes) by the length of the password

## Disclaimer

I made this project as a way to overcome boredom and to get familiar with Java. **I am in no way, shape, or form a cryptography expert**, 
so don't use this tool to protect sensitive information as **it may be vulnerable and you may also lose your files!**

## Todo
- [x] Add salt support
- [x] Store salt and make it random
- [x] Store salt in the encrypted file
- [x] Make salt position "random" in the file
