import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.security.spec.KeySpec;

/**
 * This class is responsible generating an encryption key based on a master password.
 * It uses PBKDF2 to make brute force attack slower.
 * Based on https://howtodoinjava.com/java/java-security/aes-256-encryption-decryption/\
 */
public class PBKDF2 {
    // Length of the salt in bytes
    static final int SALT_LENGTH = 64;

    // Number of iterations in PBKDF2
    static final int ITERATION_COUNT = 100000;

    // Version of the PBKDF2 algorithm
    static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA512";

    /**
     * Generate an encryption key based on a master password.
     */
    static byte[] generateKeyFromPassword(byte[] salt, byte[] password) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
        KeySpec spec = new PBEKeySpec(new String(password).toCharArray(), salt, ITERATION_COUNT, AES.KEY_LENGTH);
        SecretKey key = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
        return key.getEncoded();
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
