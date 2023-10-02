import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;

class Xor {

    /**
     * Performs a character-wise XOR (exclusive OR) operation between a text string and a key string.
     *
     * @param text The text string to be XORed with the key.
     * @param key The key string used for XORing.
     * @return A new string containing the result of the XOR operation.
     */
    public static String xorText(String text, String key) {

        StringBuilder output = new StringBuilder();

        // Xor each character in the text with the corresponding character in the key
        for (int i = 0; i < text.length(); i++) {
            output.append((char) (text.charAt(i) ^ key.charAt(i % key.length())));
        }
        return output.toString();
    }

    /**
     * Performs a byte-wise XOR (exclusive OR) operation between a byte array and a key string.
     *
     * @param bytes The byte array to be XORed with the key.
     * @param key The key string used for XORing.
     * @return A new byte array containing the result of the XOR operation.
     */
    private static byte[] xorBytes(byte[] bytes, String key) {

        byte[] output = new byte[bytes.length];
        // Xor each character in the text with the corresponding character in the key
        for (int i = 0; i < bytes.length; i++) {
            output[i] = (byte) (bytes[i] ^ key.charAt(i % key.length()));
        }
        return output;
    }

    /**
     * Displays information about a given file, including its name, path, size
     *
     * @param file The File object representing the file whose information is to be displayed.
     */
    public static void displayFileInfo(File file) {
        System.out.println("\nFile name: " + file.getName());
        System.out.println("Absolute path: " + file.getAbsolutePath());
        System.out.println("Size: " + file.length() + " bytes\n");
    }

    private static String toHex(String arg) {
        return String.format("%x", new BigInteger(1, arg.getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * Encrypts a given plaintext string using XOR operation with the provided key
     * and saves the "encrypted" data to said file.
     *
     * @param file The path to the file we want to encrypt.
     * @param key The encryption key used for the XOR operation.
     * @throws Exception If any error occurs during the operation process or if the file is too big.
     */
    public static void toFile(String file, String key) throws Exception {

        // Check if file exists
        File inputFile = new File(file);
        if (!inputFile.exists() || !inputFile.isFile()) {
            System.err.println("File does not exist");
            System.exit(1);
        }
        displayFileInfo(inputFile);

        FileInputStream inputFileStream = new FileInputStream(file);
        byte[] inputBytes = new byte[(int) inputFile.length()];

        // Check if file isn't too large
        if (inputFile.length() != inputBytes.length) {
            throw new Exception("File too large, aborting");
        }

        // Read file contents
        inputFileStream.read(inputBytes);
        inputFileStream.close();

        FileOutputStream outputFileStream = new FileOutputStream(file);
        byte[] outputBytes = xorBytes(inputBytes, key);
        outputFileStream.write(outputBytes);
        outputFileStream.close();
    }
}
