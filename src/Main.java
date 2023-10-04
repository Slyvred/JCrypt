import javax.crypto.Cipher;

public class Main {

    public static void main(String[] args) {

        Menu.encryptionMethod option = Menu.displayMenu();

        switch (option) {
            case XOR_TEXT:
                Menu.xorText();
                break;
            case XOR_FILE:
                Menu.xorFile();
                break;
            case AES_ENCRYPT_FILE:
                Menu.aesFile(Cipher.ENCRYPT_MODE);
                break;
            case AES_DECRYPT_FILE:
                Menu.aesFile(Cipher.DECRYPT_MODE);
                break;
            case AES_ENCRYPT_FOLDER:
                Menu.aesFolder(Cipher.ENCRYPT_MODE);
                break;
            case AES_DECRYPT_FOLDER:
                Menu.aesFolder(Cipher.DECRYPT_MODE);
                break;
            case EXIT:
                System.exit(0);
                break;
            default:
                System.err.println("Invalid option");
                System.exit(1);
                break;
        }
    }
}