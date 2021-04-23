import java.io.File;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.Scanner;

/**
 * Main class used by the password manager.
 * @author Piotr Smietana
 * @version 04/09/2021
 */
public class PasswordManager {
    // File with stored passwords
    static final File storedPasswordsFile = new File(
            System.getProperty("user.dir") + "/stored_passwords"
    );

    // File with a master password
    static final File masterPasswordFile = new File(
            System.getProperty("user.dir") + "/master_password"
    );

    // Salt that is used to derive a symmetric key
    static byte[] encryptionSalt;

    // IV that is used in the encryption
    static byte[] encryptionIv;

    // Key that is used in the encryption
    static byte[] encryptionKey;

    // Salt that is used to derive a symmetric key
    static byte[] hmacSalt;

    // Key that is used in HMAC
    protected static byte[] hmacKey;

    /**
     * Main menu for the password manager.
     * This is an interactive REPL.
     */
    private static void menu() throws Exception {
        String operations = "Available operations: \n"
                + "i,integrity   Check integrity of the file with passwords.\n"
                + "p,print       Print domains and usernames for all stored records.\n"
                + "g,get         Get an existing password for a domain and username.\n"
                + "s,store       Store a password for a domain and username.\n"
                + "c,change      Change an existing password for a domain and username.\n"
                + "r,remove      Remove an existing password for a domain and username.\n"
                + "h,help        Print usage.\n"
                + "e,exit        Exit.\n";
        System.out.println(operations);

        Scanner sc = new Scanner(System.in);
        System.out.print("Enter an operation: ");

        while (true) {
            String operation = sc.next().toLowerCase();
            switch (operation) {
                case "i", "integrity" -> {
                    if (checkIntegrity()) {
                        Utilities.printColor("Integrity check passed!\n", "green");
                        menu();
                    } else {
                        Utilities.printColor("Integrity check failed. Exiting...", "red");
                        System.exit(0);
                    }
                }
                case "p", "print" -> {
                    Account.printRecords();
                    menu();
                }
                case "g", "get" -> {
                    Account.getPassword();
                    menu();
                }
                case "s", "store" -> {
                    Account.storePassword();
                    menu();
                }
                case "c", "change" -> {
                    Account.changePassword();
                    menu();
                }
                case "r", "remove" -> {
                    Account.removePassword();
                    menu();
                }
                case "h", "help" -> menu();
                case "e", "exit" -> {
                    System.out.println("Exiting...");
                    System.exit(0);
                }
                default -> {
                    Utilities.printColor("Operation not recognized! Try again.\n", "red");
                    System.out.print("Enter an operation: ");
                }
            }
        }
    }

    /**
     * Main method.
     */
    public static void main(String[] args) {
        // Welcome the user
        Utilities.printColor("Welcome to HawkPass, a secure password manager!", "yellow");

        // Catch eny exceptions
        try {
            // Check if this is the first time using the password manager
            if (isFirstTime()) {
                setup();
                menu();
            } else {
                if (login()) {
                    menu();
                }
            }
        } catch (Exception e) {
            System.err.println("Exiting...");
            System.exit(1);
        }
    }

    // Check if this is the first time using the password manager
    private static boolean isFirstTime() {
        return !(storedPasswordsFile.exists() && masterPasswordFile.exists());
    }

    // Setup the password manager
    private static void setup() throws Exception {
        // Clean any leftover files
        // If we reach this code, then one of the files could be missing
        Files.deleteIfExists(masterPasswordFile.toPath());
        Files.deleteIfExists(storedPasswordsFile.toPath());

        // Get master password
        Scanner sc = new Scanner(System.in);
        System.out.println("This is your first time using the password manager. You must create a master password.");
        byte[] masterPassword = Utilities.manualOrRandomPasswordFeature(sc).getBytes();

        // Generate master password file
        byte[] salt = PBKDF2.generateSalt();
        byte[] key = PBKDF2.generateHashFromPassword(salt, masterPassword);
        byte[] saltAndKey = Utilities.addBytes(salt, key);
        Utilities.writeBytesToFile(saltAndKey, masterPasswordFile);

        // Generate stored passwords file
        encryptionSalt = PBKDF2.generateSalt();
        encryptionIv = AES.generateIV();
        encryptionKey = PBKDF2.generateKeyFromPassword(encryptionSalt, masterPassword);

        hmacSalt = PBKDF2.generateSalt();
        hmacKey = PBKDF2.generateKeyFromPassword(hmacSalt, masterPassword);

        byte[] encryptedData = AES.encrypt(encryptionIv, encryptionKey, new byte[0]);
        encryptedData = Utilities.addBytes(encryptionSalt, encryptionIv, encryptedData);
        byte[] hmac = HMAC.generateHmac(hmacKey, encryptedData);
        encryptedData = Utilities.addBytes(hmacSalt, hmac, encryptedData);
        Utilities.writeBytesToFile(encryptedData, storedPasswordsFile);

        Utilities.printColor("Master password created successfully!\n", "green");
    }

    // Login the user
    private static boolean login() throws Exception {
        Scanner sc = new Scanner(System.in);

        // Track the number of failed login attempts
        int totalAttempts = 3;
        while (totalAttempts > 0) {
            System.out.print("Enter your master password: ");
            byte[] masterPassword = sc.next().getBytes();

            // If master password is correct
            if (checkPassword(masterPassword)) {
                // Extract salts, IVs, and encrypted data
                byte[] bytes = Utilities.readFileToBytes(storedPasswordsFile);
                ByteBuffer buffer = ByteBuffer.wrap(bytes);

                hmacSalt = new byte[PBKDF2.SALT_LENGTH];
                buffer.get(hmacSalt);

                hmacKey = PBKDF2.generateKeyFromPassword(hmacSalt, masterPassword);

                byte[] hmac = new byte[HMAC.HMAC_LENGTH];
                buffer.get(hmac);

                encryptionSalt = new byte[PBKDF2.SALT_LENGTH];
                buffer.get(encryptionSalt);

                encryptionIv = new byte[AES.IV_LENGTH];
                buffer.get(encryptionIv);

                encryptionKey = PBKDF2.generateKeyFromPassword(encryptionSalt, masterPassword);

                // Check the integrity of the stored passwords file
                if (checkIntegrity()) {
                    Utilities.printColor("Login successful!\n", "green");
                    return true;
                } else {
                    Utilities.printColor("Integrity check failed. Exiting...", "red");
                    System.exit(0);
                }
            } else {
                System.out.println("Wrong master password!" + (totalAttempts <= 1 ? "" : " Try again."));
                totalAttempts--;
            }
        }

        if (totalAttempts == 0) {
            Utilities.printColor("Failed all login attempts. Exiting...", "red");
            System.exit(0);
        }

        return false;
    }

    // Check if the entered password and stored password are equal
    private static boolean checkPassword(byte[] enteredPassword) throws Exception {
        byte[] bytes = Utilities.readFileToBytes(masterPasswordFile);
        ByteBuffer buffer = ByteBuffer.wrap(bytes);

        byte[] salt = new byte[PBKDF2.SALT_LENGTH];
        buffer.get(salt);

        byte[] storedHashedPassword = new byte[buffer.remaining()];
        buffer.get(storedHashedPassword);

        byte[] currentHash = PBKDF2.generateHashFromPassword(salt, enteredPassword);
        return Arrays.equals(currentHash, storedHashedPassword);
    }

    // Check the integrity of the stored passwords file
    private static boolean checkIntegrity() throws Exception {
        byte[] bytes = Utilities.readFileToBytes(storedPasswordsFile);
        ByteBuffer buffer = ByteBuffer.wrap(bytes);

        byte[] hmacSalt = new byte[PBKDF2.SALT_LENGTH];
        buffer.get(hmacSalt);

        byte[] storedHmac = new byte[HMAC.HMAC_LENGTH];
        buffer.get(storedHmac);

        byte[] encryptedData = new byte[buffer.remaining()];
        buffer.get(encryptedData);

        byte[] currentHmac = HMAC.generateHmac(hmacKey, encryptedData);
        return Arrays.equals(currentHmac, storedHmac);
    }
}
