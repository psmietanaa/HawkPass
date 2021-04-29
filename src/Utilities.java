import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.ByteBuffer;
import java.util.Scanner;

import org.fusesource.jansi.Ansi;
import org.fusesource.jansi.AnsiConsole;

/**
 * This class is responsible for helper functions.
 */
public class Utilities {
    /**
     * Add multiple byte arrays together.
     */
    static byte[] addBytes(byte[]... bytes) {
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
    static byte[] readFileToBytes(File file) {
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
    static void writeBytesToFile(byte[] bytes, File file) {
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
     * Get a valid input from the user
     */
    static String getValidInput(Scanner sc, String question) {
        System.out.print(question);
        String input = sc.next();
        while (!checkInputConstraints(input)) {
            System.out.print(question);
            input = sc.next();
        }
        return input;
    }

    /**
     * Check input constraints
     */
    static boolean checkInputConstraints(String input) {
        int minimumLength = 4;
        int maximumLength = 80;
        if (input.length() < minimumLength) {
            System.out.println("Input must be at least " + minimumLength + " characters long!");
            return false;
        } else if (input.length() > maximumLength) {
            System.out.println("Input must be less than " + maximumLength + " characters long!");
            return false;
        }
        return true;
    }

    /**
     * Feature that allows a user to enter their password or generate one
     */
    static String manualOrRandomPasswordFeature(Scanner sc) {
        System.out.print("Would you like to use a random password generator? (y/n) ");
        String answer = sc.next().toLowerCase();
        while (!(answer.equals("y") || answer.equals("yes") || answer.equals("n") || answer.equals("no"))) {
            System.out.print("Wrong answer. Please enter (y/n) ");
            answer = sc.next().toLowerCase();
        }

        String password;
        if (answer.equals("y") || answer.equals("yes")) {
            password = GeneratePassword.generateRandomPassword();
            printColor("Your randomly generated password is: " + password, "green");
        } else {
            password = getValidInput(sc, "Enter your password: ");
        }
        return password;
    }

    /**
     * Print input in color using Jansi library
     * Color can be black, red, green, yellow, blue, magenta, cyan, or white.
     */
    static void printColor(String input, String colorName) {
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
