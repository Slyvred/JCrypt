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
            case AES_ENCRYPT:
                Menu.aesFile(Cipher.ENCRYPT_MODE);
                break;
            case AES_DECRYPT:
                Menu.aesFile(Cipher.DECRYPT_MODE);
                break;
            case EXIT:
                System.exit(0);
                break;
            default:
                System.out.println("Invalid option");
                System.exit(1);
                break;
        }
    }
}