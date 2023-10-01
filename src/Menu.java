import javax.crypto.Cipher;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;
import javax.crypto.SecretKey;


public class Menu {

    public enum encryptionMethod {
        _pad,
        XOR_TEXT,
        XOR_FILE,
        AES_ENCRYPT,
        AES_DECRYPT,
        EXIT
    }
    private static final String ANSI_BLUE = "\u001B[34m";
    private static final String ANSI_RESET = "\u001B[0m";

    private static void printOutput(String output) {
        System.out.println(ANSI_BLUE + output + ANSI_RESET);
    }

    public static encryptionMethod displayMenu() {
        System.out.println("-==== JCrypt - By Slyvred ====-");
        System.out.println("1. Xor text\n2. Xor file\n3. Encrypt file (AES-256)\n4. Decrypt file (AES-256)\n5. Exit");
        System.out.print("Select an option: ");
        Scanner sc = new Scanner(System.in);
        int option = 0;

        try {
            option = sc.nextInt();
        } catch (Exception e) {
            System.out.println("Error reading input");
            System.exit(1);
        }

        if (option < 1 || option > encryptionMethod.values().length) {
            System.out.println("Invalid option");
            System.exit(1);
        }

        return encryptionMethod.values()[option];
    }

    private static String getString(String prompt) {
        System.out.print(prompt + ": ");
        Scanner sc = new Scanner(System.in);
        String input = "";

        try {
            input = sc.nextLine();
        } catch (Exception e) {
            System.out.println("Error reading input");
            System.exit(1);
        }

        return input;
    }

    public static void xorText() {
        String text = getString("Enter text to xor");
        String key = getString("Enter key");
        String output = Xor.xorText(text, key);
        System.out.print("Xor'd text: ");
        printOutput(output);
    }

    public static void xorFile() {
        String path = getString("Enter file path");
        String key = getString("Enter key");
        try {
            Xor.toFile(path, key);
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
        printOutput("File Xor'd successfully");
    }

    public static void aesFile(int mode) {

        if (mode != Cipher.ENCRYPT_MODE && mode != Cipher.DECRYPT_MODE) {
            throw new IllegalArgumentException("Invalid mode");
        }

        String path = getString("Enter file path");
        String key = getString("Enter key");
        SecretKey secretKey;
        try {
            secretKey = AES.generateAESKeyFromPassword(key);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            throw new RuntimeException(ex);
        }

        try {
            AES.toFile(path, secretKey, mode);
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
        printOutput("File " +  ((mode == Cipher.ENCRYPT_MODE) ? "encrypted" : "decrypted") + " successfully");
    }
}
