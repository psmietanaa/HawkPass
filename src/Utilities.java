import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.ByteBuffer;

import org.fusesource.jansi.Ansi;
import org.fusesource.jansi.AnsiConsole;

/**
 * This class is responsible for helper functions.
 */
public class Utilities {
    /**
     * Convert a byte array to a hex string.
     */
    public static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b: bytes)
            result.append(String.format("%02x", b));
        return result.toString();
    }

    /**
     * Add multiple byte arrays together.
     */
    public static byte[] addBytes(byte[]... bytes) {
        int size = 0;
        for (byte[] b : bytes) {
            size += b.length;
        }

        ByteBuffer buffer = ByteBuffer.allocate(size);
        for (byte[] b : bytes) {
            buffer.put(b);
        }

        return buffer.array();
    }

    /**
     * Read a file to a byte array.
     */
    public static byte[] readFileToBytes(File file) {
        int fileLength = (int) file.length();
        byte[] bytes = new byte[fileLength];

        try {
            FileInputStream fileInputStream = new FileInputStream(file);
            fileInputStream.read(bytes);
            fileInputStream.close();
        } catch (Exception e) {
            System.err.println(e.toString());
            System.exit(1);
        }

        return bytes;
    }

    /**
     * Write a byte array into a file.
     */
    public static void writeBytesToFile(byte[] bytes, File file) {
        try {
            FileOutputStream writer = new FileOutputStream(file);
            writer.write(bytes);
            writer.flush();
            writer.close();
        } catch (Exception e) {
            System.err.println(e.toString());
            System.exit(1);
        }
    }

    /**
     * Print input in color using Jansi library
     * Color can be black, red, green, yellow, blue, magenta, cyan, or white.
     */
    public static void printColor(String input, String colorName) {
        try {
            AnsiConsole.systemInstall();
            Ansi.Color color = Ansi.Color.valueOf(colorName.toUpperCase());
            AnsiConsole.out().println(Ansi.ansi().fg(color).a(input).reset());
            AnsiConsole.systemUninstall();
        } catch (Exception e) {
            System.out.println(input);
        }
    }
}
