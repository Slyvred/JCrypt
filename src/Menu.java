import javax.crypto.Cipher;
import java.io.File;
import java.util.Scanner;


public class Menu {

    public enum encryptionMethod {
        _pad,
        XOR_TEXT,
        XOR_FILE,
        AES_ENCRYPT_FILE,
        AES_DECRYPT_FILE,
        AES_ENCRYPT_FOLDER,
        AES_DECRYPT_FOLDER,
        EXIT
    }

    private static final String ANSI_BLUE = "\u001B[34m";
    private static final String ANSI_RESET = "\u001B[0m";

    private static int countFiles(File folder) throws IllegalArgumentException {

        if (!folder.isDirectory()) {
            throw new IllegalArgumentException("Argument must be a directory");
        }

        int count = 0;
        for (File file : folder.listFiles()) {
            if (file.isDirectory()) {
                count += countFiles(file);
            } else {
                count++;
            }
        }
        return count;
    }

    private static void printOutput(String output) {
        System.out.println(ANSI_BLUE + output + ANSI_RESET);
    }

    public static encryptionMethod displayMenu() {
        System.out.println("\n<====== JCrypt - By Slyvred ======>");
        System.out.println("XOR and AES-256 encryption tool\n");

        System.out.println(
                """
                        1. Xor text
                        2. Xor file
                        3. Encrypt file (AES-256)
                        4. Decrypt file (AES-256)
                        5. Encrypt folder (AES-256)
                        6. Decrypt folder (AES-256)
                        7. Exit"""
        );

        System.out.println();
        System.out.print("Select an option: ");
        Scanner sc = new Scanner(System.in);
        int option = 0;

        try {
            option = sc.nextInt();
        } catch (Exception e) {
            System.err.println("Error reading input");
            System.exit(1);
        }

        if (option < 1 || option > encryptionMethod.values().length) {
            System.err.println("Invalid option");
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
            System.err.println("Error reading input");
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

        try {
            if (mode == Cipher.ENCRYPT_MODE) {
                AES.encryptFile(path, key, true);
            } else {
                AES.decryptFile(path, key, true);
            }
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }

        printOutput("File " + ((mode == Cipher.ENCRYPT_MODE) ? "encrypted" : "decrypted") + " successfully");
    }

    public static void aesFolder(int mode) {

        if (mode != Cipher.ENCRYPT_MODE && mode != Cipher.DECRYPT_MODE) {
            throw new IllegalArgumentException("Invalid mode");
        }

        String path = getString("Enter folder path");
        String key = getString("Enter key");

        // Get number of files in folder including subfolders
        int numFiles = countFiles(new File(path));

        try {
            if (mode == Cipher.ENCRYPT_MODE) {
                AES.encryptFolder(path, key);
            } else {
                AES.decryptFolder(path, key);
            }
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }

        printOutput("\n\nFolder " + ((mode == Cipher.ENCRYPT_MODE) ? "encrypted" : "decrypted") + " successfully");
        printOutput("Files " + ((mode == Cipher.ENCRYPT_MODE) ? "encrypted" : "decrypted") + ": " + numFiles);
    }
}
