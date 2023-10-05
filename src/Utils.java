import java.io.File;

public class Utils {

    /**
     * Displays information about a given file, including its name, path, size
     *
     * @param file The File object representing the file whose information is to be displayed.
     */
    public static int countFiles(String folder) throws IllegalArgumentException {

        File inputFolder = new File(folder);
        if (!inputFolder.isDirectory() || !inputFolder.exists()) {
            throw new IllegalArgumentException("Argument must be a directory");
        }

        int count = 0;
        for (File file : inputFolder.listFiles()) {
            if (file.isDirectory()) {
                count += countFiles(file.getAbsolutePath());
            } else {
                count++;
            }
        }
        return count;
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
}
