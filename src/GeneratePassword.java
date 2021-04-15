import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * This class is responsible for generating a secure random password that consists of at least
 * two lowercase characters, two uppercase characters, two digits, and two special characters.
 * Based on https://mkyong.com/java/java-password-generator-example
 */
public class GeneratePassword {
    // Allowed characters
    private static final String lowercase = "abcdefghijklmnopqrstuvwxyz";
    private static final String uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String digits = "1234567890";
    private static final String special = "!@#$%^&*()[]{}";
    private static final String allowed = lowercase + uppercase + digits + special;

    // Password length
    private static final int length = 32;

    // Secure random number generator
    private static final SecureRandom random = new SecureRandom();

    /**
     * Generate a secure and unpredictable password. It consists of at least two lowercase
     * characters, two uppercase characters, two digits, and two special characters.
     */
    static String generateRandomPassword() {
        String password = generateRandomString(lowercase, 2) +
                generateRandomString(uppercase, 2) +
                generateRandomString(digits, 2) +
                generateRandomString(special, 2) +
                generateRandomString(allowed, length - 8);
        return shuffleString(password);
    }

    // Generate a random string from allowed characters
    private static String generateRandomString(String allowedCharacters, int length) {
        StringBuilder string = new StringBuilder();
        for (int i = 0; i < length; i++) {
            int index = random.nextInt(allowedCharacters.length());
            string.append(allowedCharacters.charAt(index));
        }
        return string.toString();
    }


    // Shuffle a string
    private static String shuffleString(String string) {
        List<String> list = Arrays.asList(string.split(""));
        Collections.shuffle(list);
        return String.join("", list);
    }
}
