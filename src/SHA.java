import java.security.MessageDigest;
import java.security.SecureRandom;

/**
 * This class is responsible for hashing.
 * It uses SHA3-512 algorithm.
 * Based on https://mkyong.com/java/java-sha-hashing-example
 */
public class SHA {
    // Length of the salt in bytes
    protected static final int SALT_LENGTH = 64;

    // Version of the hashing algorithm
    protected static final String SHA_ALGORITHM = "SHA3-512";

    /**
     * Generate a salted hash from a given input.
     */
    protected static byte[] generateHash(byte[] salt, byte[] input) throws Exception {
        MessageDigest md = MessageDigest.getInstance(SHA_ALGORITHM);
        md.update(salt);
        byte[] hash = md.digest(input);
        return hash;
    }

    /**
     * Generate a salt.
     */
    protected static byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[SALT_LENGTH];
        random.nextBytes(salt);
        return salt;
    }
}
