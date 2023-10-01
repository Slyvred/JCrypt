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

public class AES {
    @Deprecated
    private static SecretKey generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256); // AES key size (128, 192 or 256 bits)
        return keyGenerator.generateKey();
    }

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

    // The salt should be generated once and stored somewhere
    // The same salt should be used for decryption
    private static byte[] generateSalt() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] salt = new byte[16]; // 128 bits salt (16 Bytes)
        secureRandom.nextBytes(salt);
        return salt;
    }

    private static byte[] concatBytes(byte[] array1, byte[] array2) {
        int length1 = array1.length;
        int length2 = array2.length;

        byte[] result = new byte[length1 + length2];

        System.arraycopy(array1, 0, result, 0, length1);

        System.arraycopy(array2, 0, result, length1, length2);

        return result;
    }

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

        FileOutputStream outputFileStream = new FileOutputStream(file);
//        byte[] finalBytes = concatBytes(salt, outputBytes);
        outputFileStream.write(outputBytes);
        outputFileStream.close();

        FileOutputStream saltFileStream = new FileOutputStream(file + ".salt");
        saltFileStream.write(salt);
        saltFileStream.close();
    }

    public static void decryptFile(String file, String key) throws Exception {

        // Check if file exists
        File _file = new File(file);
        if (!_file.exists() || !_file.isFile()) {
            System.err.println("File does not exist");
            System.exit(1);
        }
        Xor.displayFileInfo(_file);

        Cipher cipher = Cipher.getInstance("AES");

        // Get salt from file (first 16 bytes)
//        FileInputStream inputFileStream = new FileInputStream(file);
        byte[] salt = new byte[16];
//        inputFileStream.read(salt);

        FileInputStream saltFileStream = new FileInputStream(file + ".salt");
        saltFileStream.read(salt);
        saltFileStream.close();

        SecretKey secretKey;
        try {
            secretKey = generateAESKeyFromPassword(key, salt);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            throw new RuntimeException(ex);
        }

        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        byte[] inputBytes = new byte[(int)_file.length()];

        if (_file.length() != inputBytes.length) {
            throw new Exception("File too large, aborting");
        }

        // Read file contents (after salt)
        FileInputStream inputFileStream = new FileInputStream(file);
        inputFileStream.read(inputBytes);
        inputFileStream.close();

        byte[] outputBytes = inputBytes;
        try {
            outputBytes = cipher.doFinal(inputBytes);
        } catch (Exception e) {
            System.err.println("Error running AES, check key");
            System.exit(1);
        }

        FileOutputStream outputFileStream = new FileOutputStream(file);
        outputFileStream.write(outputBytes);
        outputFileStream.close();

        // Delete salt file
        File saltFile = new File(file + ".salt");
        saltFile.delete();
    }
}