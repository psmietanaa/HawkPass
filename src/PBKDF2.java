import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.SecureRandom;

/**
 * This class is responsible generating an encryption key based on a master password.
 * It is also responsible for generating a hash of the master password.
 * PBKDF2 is designed to be computationally expensive to make brute-force attacks harder.
 * Based on https://howtodoinjava.com/java/java-security/aes-256-encryption-decryption
 * https://www.codeproject.com/Articles/704865/Salted-Password-Hashing-Doing-it-Right
 */
public class PBKDF2 {
    // Length of the salt in bytes
    static final int SALT_LENGTH = 64;

    // Length of the encryption key in bits
    static final int KEY_LENGTH = 256;

    // Length of the hash in bits
    static final int HASH_LENGTH = 512;

    // Number of iterations in PBKDF2
    static final int ITERATION_COUNT = 65536;

    // Version of the PBKDF2 algorithm
    static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA512";

    /**
     * Generate an encryption key based on a master password.
     */
    static byte[] generateKeyFromPassword(byte[] salt, byte[] password) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
        PBEKeySpec spec = new PBEKeySpec(new String(password).toCharArray(), salt, ITERATION_COUNT, KEY_LENGTH);
        return factory.generateSecret(spec).getEncoded();
    }

    /**
     * Generate a hash of the master password.
     */
    static byte[] generateHashFromPassword(byte[] salt, byte[] password) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
        PBEKeySpec spec = new PBEKeySpec(new String(password).toCharArray(), salt, ITERATION_COUNT, HASH_LENGTH);
        return factory.generateSecret(spec).getEncoded();
    }

    /**
     * Generate a salt.
     */
    static byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[SALT_LENGTH];
        random.nextBytes(salt);
        return salt;
    }
}
