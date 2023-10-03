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

## Disclaimer

I made this project as a way to overcome boredom and to get familiar with Java. **I am in no way, shape, or form a cryptography expert**, 
so don't use this tool to protect sensitive information as **it may be vulnerable and you may also lose your files!**

## Todo
- [x] Add salt support
- [x] Store salt and make it random
- [x] Store salt in the encrypted file
- [x] Make salt position "random" in the file
