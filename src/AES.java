import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.lang.reflect.Array;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

public class AES {

    /**
     * Generates a random AES (Advanced Encryption Standard) secret key.
     *
     * @return A randomly generated AES SecretKey.
     * @throws NoSuchAlgorithmException If the specified cryptographic algorithm is not available.
     */
    @Deprecated
    private static SecretKey generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256); // AES key size (128, 192 or 256 bits)
        return keyGenerator.generateKey();
    }

    /**
     * Generates an AES (Advanced Encryption Standard) secret key from a password and a salt
     * using a key derivation function (KDF).
     *
     * @param password The password from which the key will be derived.
     * @param salt A byte array representing the salt used in the key derivation.
     * @return A SecretKey generated from the password and salt.
     * @throws NoSuchAlgorithmException If the specified cryptographic algorithm is not available.
     * @throws InvalidKeySpecException If the provided key specification is invalid.
     */
    public static SecretKey generateAESKeyFromPassword(String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        // PBKDF2 settings
        String algorithm = "PBKDF2WithHmacSHA256";
        int keyLength = 256; // Matches AES key size
        int iterations = 10000; // Higher iterations = better security but slower

        // Generate AES key from password
        char[] passwordChars = password.toCharArray();
        KeySpec keySpec = new PBEKeySpec(passwordChars, salt, iterations, keyLength);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(algorithm);
        byte[] keyBytes = keyFactory.generateSecret(keySpec).getEncoded();

        // Return AES key
        return new SecretKeySpec(keyBytes, "AES");
    }

    /**
     * Generates a random salt of 128 bits (16 bytes) using a cryptographically secure random number generator.
     * The salt should be generated once and stored somewhere.
     * The same salt should be used for decryption.
     *
     * @return A byte array containing the generated salt.
     */
    private static byte[] generateSalt() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] salt = new byte[16]; // 128 bits salt (16 Bytes)
        secureRandom.nextBytes(salt);
        return salt;
    }

    /**
     * Concatenates two byte arrays, `array1` followed by `array2`, and returns the result as a new byte array.
     *
     * @param array1 The first byte array to be concatenated.
     * @param array2 The second byte array to be concatenated.
     * @return A new byte array containing the concatenated data.
     */
    private static byte[] concatBytes(byte[] array1, byte[] array2) {
        int length1 = array1.length;
        int length2 = array2.length;
        byte[] result = new byte[length1 + length2];

        System.arraycopy(array1, 0, result, 0, length1);
        System.arraycopy(array2, 0, result, length1, length2);

        return result;
    }


    /**
     * Encrypts a file using AES encryption with a provided key and saves the encrypted
     * data back to the same file. This method generates a random salt for key derivation
     * and uses it along with the provided key to initialize the encryption process.
     *
     * @param file The path to the file to be encrypted.
     * @param key The encryption key used for AES encryption.
     * @throws Exception If any error occurs during the encryption process or if the file is too large.
     */
    public static void encryptFile(String file, String key) throws Exception {

        // Check if file exists
        File _file = new File(file);
        if (!_file.exists() || !_file.isFile()) {
            System.err.println("File does not exist");
            System.exit(1);
        }
        Xor.displayFileInfo(_file);

        Cipher cipher = Cipher.getInstance("AES");

        // Generate salt if encrypting
        byte[] salt = generateSalt();

        SecretKey secretKey;
        try {
            secretKey = generateAESKeyFromPassword(key, salt);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            throw new RuntimeException(ex);
        }

        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        FileInputStream inputFileStream = new FileInputStream(file);
        byte[] inputBytes = new byte[(int)_file.length()];

        if (_file.length() != inputBytes.length) {
            throw new Exception("File too large, aborting");
        }
        inputFileStream.read(inputBytes);
        inputFileStream.close();

        byte[] outputBytes = inputBytes;
        try {
            outputBytes = cipher.doFinal(inputBytes);
        } catch (Exception e) {
            System.err.println("Error running AES, check key");
            System.exit(1);
        }


        // Write salt and cipher to file
        FileOutputStream outputFileStream = new FileOutputStream(file);
        byte[] finalBytes = concatBytes(salt, outputBytes);
        outputFileStream.write(finalBytes);
        outputFileStream.close();

        // Clear secretKey, salt and cipher from memory
        secretKey = null;
        salt = null;
        cipher = null;

        // Make file read-only
        boolean readOnly = _file.setWritable(false);
        if (!readOnly) {
            System.err.println("[Warning] Couldn't set file to read-only");
        }
    }

    /**
     * Decrypts a file previously encrypted with AES encryption using the provided key.
     * This method reads the encrypted data from the file, extracts the salt and cipher,
     * and then uses the salt and key to perform decryption. The decrypted data is saved
     * back to the same file, replacing the encrypted content.
     *
     * @param file The path to the file to be decrypted.
     * @param key The decryption key used for AES decryption.
     * @throws Exception If any error occurs during the decryption process or if the file is too large.
     */
    public static void decryptFile(String file, String key) throws Exception {
        // Check if file exists
        File _file = new File(file);
        if (!_file.exists() || !_file.isFile()) {
            System.err.println("File does not exist");
            System.exit(1);
        }
        Xor.displayFileInfo(_file);

        // Make file writable
        boolean writeStatus = _file.canWrite();
        if (!writeStatus) {
            boolean writable = _file.setWritable(true);
            if (!writable) {
                System.err.println("Couldn't set file to writable, aborting");
                System.exit(1);
            }
        }

        Cipher cipher = Cipher.getInstance("AES");


        // Read file
        FileInputStream inputFileStream = new FileInputStream(file);
        byte[] saltAndCipher = new byte[(int)_file.length()];

        if (_file.length() != saltAndCipher.length) {
            throw new Exception("File too large, aborting");
        }

        inputFileStream.read(saltAndCipher);
        inputFileStream.close();

        // Get salt
        byte[] salt = Arrays.copyOfRange(saltAndCipher, 0, 16); // 16 exclusive

        // Get cipher
        byte[] inputBytes = Arrays.copyOfRange(saltAndCipher, 16, saltAndCipher.length);

        SecretKey secretKey;
        try {
            secretKey = generateAESKeyFromPassword(key, salt);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            throw new RuntimeException(ex);
        }

        salt = null; // Clear salt from memory

        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        byte[] outputBytes = inputBytes;
        try {
            outputBytes = cipher.doFinal(inputBytes);
        } catch (Exception e) {
            System.err.println("Error running AES, check key");

            // Set back to original mode
            _file.setWritable(writeStatus);

            System.exit(1);
        }

        // Clear secretKey and cipher from memory
        secretKey = null;
        cipher = null;

        FileOutputStream outputFileStream = new FileOutputStream(file);
        outputFileStream.write(outputBytes);
        outputFileStream.close();
    }

    public static void encryptFolder(String folder, String key) throws Exception {

        File inputFolder = new File(folder);
        if (!inputFolder.exists() || !inputFolder.isDirectory()) {
            System.err.println("Folder does not exist");
            System.exit(1);
        }

        File[] files = inputFolder.listFiles();
        if (files == null) {
            System.err.println("Error reading folder");
            System.exit(1);
        }

        // Encrypt each file in the folder including subfolders
        for (File file : files) {
            if (file.isFile()) {
                encryptFile(file.getAbsolutePath(), key);
            } else if (file.isDirectory()) {
                encryptFolder(file.getAbsolutePath(), key);
            }
        }
    }

public static void decryptFolder(String folder, String key) throws Exception {

        File inputFolder = new File(folder);
        if (!inputFolder.exists() || !inputFolder.isDirectory()) {
            System.err.println("Folder does not exist");
            System.exit(1);
        }

        File[] files = inputFolder.listFiles();
        if (files == null) {
            System.err.println("Error reading folder");
            System.exit(1);
        }

        // Decrypt each file in the folder including subfolders
        for (File file : files) {
            if (file.isFile()) {
                decryptFile(file.getAbsolutePath(), key);
            } else if (file.isDirectory()) {
                decryptFolder(file.getAbsolutePath(), key);
            }
        }
    }
}