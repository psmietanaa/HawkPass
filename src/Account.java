import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Scanner;

/**
 * This class is responsible for storing records in the password manager.
 * A record is a domain name, username, and password.
 * @see Account
 */
class Record implements Comparable<Record> {
    protected final String domain;
    protected final String username;
    protected final String password;

    public Record(String domain, String username, String password) {
        this.domain = domain;
        this.username = username;
        this.password = password;
    }

    @Override
    public String toString() {
        return this.domain + " " + this.username + " " + this.password;
    }

    @Override
    public int compareTo(Record r) {
        return this.domain.compareTo(r.domain);
    }
}

/**
 * This class is responsible for managing stored records.
 * @see Record
 */
public class Account {
    /**
     * Read records and decrypt them.
     */
    private static ArrayList<Record> readRecords() throws Exception {
        byte[] bytes = Utilities.readFileToBytes(PasswordManager.storedPasswordsFile);

        // Offset of encrypted data
        int offset = PBKDF2.SALT_LENGTH + HMAC.HMAC_LENGTH + PBKDF2.SALT_LENGTH + AES.IV_LENGTH;
        byte[] encryptedData = Arrays.copyOfRange(bytes, offset, bytes.length);

        // Decrypt the data
        byte[] decryptedData = AES.decrypt(PasswordManager.encryptionIv, PasswordManager.encryptionKey, encryptedData);

        ArrayList<Record> records = new ArrayList<>();
        Scanner readFile = new Scanner(new String(decryptedData));
        while (readFile.hasNextLine()) {
            String line = readFile.nextLine();
            String[] fields = line.split("\\s+");
            Record record = new Record(fields[0], fields[1], fields[2]);
            records.add(record);
        }
        return records;
    }

    /**
     * Save records and encrypt them.
     */
    private static void saveRecords(ArrayList<Record> records) throws Exception {
        // Convert records to a list of strings
        ArrayList<String> recordsString = new ArrayList<>();
        for (Record record : records) {
            recordsString.add(record.toString());
        }
        byte[] data = String.join(System.lineSeparator(), recordsString).getBytes();

        // Generate a new IV
        PasswordManager.encryptionIv = AES.generateIV();

        // Generate stored passwords file
        byte[] encryptedData = AES.encrypt(PasswordManager.encryptionIv, PasswordManager.encryptionKey, data);
        encryptedData = Utilities.addBytes(PasswordManager.encryptionSalt, PasswordManager.encryptionIv, encryptedData);

        byte[] hmac = HMAC.generateHmac(PasswordManager.hmacKey, encryptedData);
        encryptedData = Utilities.addBytes(PasswordManager.hmacSalt, hmac, encryptedData);

        Utilities.writeBytesToFile(encryptedData, PasswordManager.storedPasswordsFile);
    }

    /**
     * Store a password for a domain and username.
     * The user has the option to use a random password generator.
     */
    protected static void storePassword() throws Exception {
        Scanner sc = new Scanner(System.in);
        ArrayList<Record> records = readRecords();

        String domain = getValidInput(sc, "Enter domain name: ").toLowerCase();

        String username = getValidInput(sc, "Enter username: ");

        if (checkIfRecordExists(domain, username, records)) {
            Utilities.printColor("Record already exists with this domain and username!\n", "red");
        } else {
            System.out.print("Would you like to use a random password generator (Y/N)? ");
            String answer = sc.next().toLowerCase();
            while (!(answer.equals("y") || answer.equals("yes") || answer.equals("n") || answer.equals("no"))) {
                System.out.print("Wrong answer. Please enter (Y/N): ");
                answer = sc.next().toLowerCase();
            }

            String password;
            if (answer.equals("y") || answer.equals("yes")) {
                password = GeneratePassword.generateRandomPassword();
                System.out.println("Your randomly generated password is: " + password);
            } else {
                password = getValidInput(sc, "Enter your password: ");
            }

            Record record = new Record(domain, username, password);
            records.add(record);
            Collections.sort(records);
            saveRecords(records);
            Utilities.printColor("Record stored successfully!\n", "green");
        }
    }

    /**
     * Change a password for a domain and username.
     * The user has the option to use a random password generator.
     */
    protected static void changePassword() throws Exception {
        Scanner sc = new Scanner(System.in);
        ArrayList<Record> records = readRecords();
        if (records.isEmpty()) {
            Utilities.printColor("Cannot change a password because the password manager is empty!\n", "red");
            return;
        }

        String domain = getValidInput(sc, "Enter domain name: ").toLowerCase();
        if (!checkIfDomainExists(domain, records)) {
            Utilities.printColor("Record doesn't exist with this domain!\n", "red");
            return;
        }

        String username = getValidInput(sc, "Enter username: ");

        if (checkIfRecordExists(domain, username, records)) {
            records.removeIf(record -> record.domain.equals(domain) && record.username.equals(username));

            System.out.print("Would you like to use a random password generator (Y/N)? ");
            String answer = sc.next().toLowerCase();
            while (!(answer.equals("y") || answer.equals("yes") || answer.equals("n") || answer.equals("no"))) {
                System.out.print("Wrong answer. Please enter (Y/N): ");
                answer = sc.next().toLowerCase();
            }

            String password;
            if (answer.equals("y") || answer.equals("yes")) {
                password = GeneratePassword.generateRandomPassword();
                System.out.println("Your randomly generated password is: " + password);
            } else {
                password = getValidInput(sc, "Enter your password: ");
            }

            Record record = new Record(domain, username, password);
            records.add(record);
            Collections.sort(records);
            saveRecords(records);
            Utilities.printColor("Record changed successfully!\n", "green");
        } else {
            Utilities.printColor("Record doesn't exist with this domain and username!\n", "red");
        }
    }

    /**
     * Remove a password for a domain and username.
     */
    protected static void removePassword() throws Exception {
        Scanner sc = new Scanner(System.in);
        ArrayList<Record> records = readRecords();
        if (records.isEmpty()) {
            Utilities.printColor("Cannot remove a password because the password manager is empty!\n", "red");
            return;
        }

        String domain = getValidInput(sc, "Enter domain name: ").toLowerCase();
        if (!checkIfDomainExists(domain, records)) {
            Utilities.printColor("Record doesn't exist with this domain!\n", "red");
            return;
        }

        String username = getValidInput(sc, "Enter username: ");

        if (checkIfRecordExists(domain, username, records)) {
            records.removeIf(record -> record.domain.equals(domain) && record.username.equals(username));
            Collections.sort(records);
            saveRecords(records);
            Utilities.printColor("Record deleted successfully!\n", "green");
        } else {
            Utilities.printColor("Record doesn't exist with this domain and username!\n", "red");
        }
    }

    /**
     * Get a password for a domain and username.
     */
    protected static void getPassword() throws Exception {
        Scanner sc = new Scanner(System.in);
        ArrayList<Record> records = readRecords();
        if (records.isEmpty()) {
            Utilities.printColor("Cannot get a password because the password manager is empty!\n", "red");
            return;
        }

        String domain = getValidInput(sc, "Enter domain name: ").toLowerCase();
        if (!checkIfDomainExists(domain, records)) {
            Utilities.printColor("Record doesn't exist with this domain!\n", "red");
            return;
        }

        String username = getValidInput(sc, "Enter username: ");

        if (checkIfRecordExists(domain, username, records)) {
            for (Record record : records) {
                if (domain.equals(record.domain) && username.equals(record.username)) {
                    System.out.println("Stored password for this account is: " + record.password + "\n");
                }
            }
        } else {
            Utilities.printColor("Record doesn't exist with this domain and username!\n", "red");
        }
    }

    // Get a valid input from the user
    private static String getValidInput(Scanner sc, String question) {
        System.out.print(question);
        String input = sc.next();
        while (!checkInputConstraints(input)) {
            System.out.print(question);
            input = sc.next();
        }
        return input;
    }

    // Check input constraints
    private static boolean checkInputConstraints(String input) {
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

    // Check if a password already exists for a specific domain
    private static boolean checkIfDomainExists(String domain, ArrayList<Record> records) {
        for (Record record : records) {
            if (domain.equals(record.domain)) {
                return true;
            }
        }
        return false;
    }

    // Check if a password already exists for a specific domain and username
    private static boolean checkIfRecordExists(String domain, String username, ArrayList<Record> records) {
        for (Record record : records) {
            if (domain.equals(record.domain) && username.equals(record.username)) {
                return true;
            }
        }
        return false;
    }
}
