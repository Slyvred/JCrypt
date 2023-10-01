import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
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

    public static SecretKey generateAESKeyFromPassword(String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        // PBKDF2 settings
        String algorithm = "PBKDF2WithHmacSHA256";
        int keyLength = 256; // Matches AES key size
        int iterations = 10000; // Higher iterations = better security but slower

        // Generate AES key from password
        char[] passwordChars = password.toCharArray();
        byte[] salt = generateSalt(); // Add salt for more security
        KeySpec keySpec = new PBEKeySpec(passwordChars, salt, iterations, keyLength);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(algorithm);
        byte[] keyBytes = keyFactory.generateSecret(keySpec).getEncoded();

        // Return AES key
        return new SecretKeySpec(keyBytes, "AES");
    }

    // The salt should be generated once and stored somewhere
    // The same salt should be used for decryption
    // Currently the salt isn't stored anywhere or randomized so this is fucking stupid
    private static byte[] generateSalt() {
        // Generate 16 bytes salt (128 bits)
        byte[] salt = new byte[16];
        for (int i = 0; i < salt.length; i++) {
            salt[i] = (byte) i;
//            salt[i] = SecureRandom.getSeed(1)[0];
        }
        return salt;
    }

    public static void toFile(String inputFile, String outputFile, SecretKey secretKey, int mode) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(mode, secretKey);

        // Check if file exists
        File _file = new File(inputFile);
        if (!_file.exists() || !_file.isFile()) {
            System.err.println("File does not exist");
            System.exit(1);
        }
        Xor.displayFileInfo(_file);

        FileInputStream inputFileStream = new FileInputStream(inputFile);
        FileOutputStream outputFileStream = new FileOutputStream(outputFile);

        byte[] inputBytes = new byte[(int) _file.length()];

        if (_file.length() != inputBytes.length) {
            throw new Exception("File too large, aborting");
        }
        inputFileStream.read(inputBytes);
        inputFileStream.close();

        byte[] encryptedBytes = cipher.doFinal(inputBytes);
        outputFileStream.write(encryptedBytes);
        outputFileStream.close();
    }

    public static void toFile(String file, SecretKey secretKey, int mode) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(mode, secretKey);

        // Check if file exists
        File _file = new File(file);
        if (!_file.exists() || !_file.isFile()) {
            System.err.println("File does not exist");
            System.exit(1);
        }
        Xor.displayFileInfo(_file);

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
        outputFileStream.write(outputBytes);
        outputFileStream.close();
    }
}