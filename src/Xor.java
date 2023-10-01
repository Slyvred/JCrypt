import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;

class Xor {
    public static String xorText(String text, String key) {

        StringBuilder output = new StringBuilder();

        // Xor each character in the text with the corresponding character in the key
        for (int i = 0; i < text.length(); i++) {
            output.append((char) (text.charAt(i) ^ key.charAt(i % key.length())));
        }
        return output.toString();
    }

    private static byte[] xorBytes(byte[] bytes, String key) {

        byte[] output = new byte[bytes.length];

        // Xor each character in the text with the corresponding character in the key
        for (int i = 0; i < bytes.length; i++) {
            output[i] = (byte) (bytes[i] ^ key.charAt(i % key.length()));
        }
        return output;
    }

    // Display file information
    public static void displayFileInfo(File file) {
        System.out.println("\nFile name: " + file.getName());
        System.out.println("Absolute path: " + file.getAbsolutePath());
        System.out.println("Size: " + file.length() + " bytes\n");
    }

    private static String toHex(String arg) {
        return String.format("%x", new BigInteger(1, arg.getBytes(StandardCharsets.UTF_8)));
    }

    public static void toFile(String file, String key) throws Exception {

        // Check if file exists
        File _file = new File(file);
        if (!_file.exists() || !_file.isFile()) {
            System.err.println("File does not exist");
            System.exit(1);
        }
        displayFileInfo(_file);

        FileInputStream inputFileStream = new FileInputStream(file);
        byte[] inputBytes = new byte[(int) _file.length()];

        // Check if file isn't too large
        if (_file.length() != inputBytes.length) {
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

    @Deprecated
    private static void xorFile(String path, String key) {

        // Check if file exists
        File file = new File(path);
        if (!file.exists() || !file.isFile()) {
            System.out.println("File does not exist");
            System.exit(1);
        }
        displayFileInfo(file);

        System.out.println("Xor'ing file...");
        // Read file contents line by line
        StringBuilder output = new StringBuilder();
        try {
            Scanner reader = new Scanner(file);
            reader.useDelimiter("\n");
            while (reader.hasNextLine()) {
                output.append(reader.nextLine()); // Xor each line
            }
            reader.close();

        } catch (Exception e) {
            System.out.println("Error reading file");
            System.exit(1);
        }

        System.out.println("Writing to file...");
        // Write output to file
        try {
            String newFilePath = path + (path.contains(".xor") ? "" : ".xor");
            FileWriter writer = new FileWriter(newFilePath);
            writer.write(xorText(output.toString(), key));
            writer.close();
        } catch (Exception e) {
            System.out.println("Error writing to file");
            System.exit(1);
        }
        System.out.println("Done");
    }
}
