import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

/**
 * This class is responsible for encryption and decryption.
 * It uses AES-256 with CBC mode and PKCS5 padding.
 */
public class AES {
    // Length of the IV in bytes
    // AES has a 128 block size
    static final int IV_LENGTH = 16;

    // Version of the AES algorithm
    static final String AES_ALGORITHM = "AES/CBC/PKCS5Padding";

    /**
     * Encrypt a given input using an iv and a key.
     */
    static byte[] encrypt(byte[] iv, byte[] key, byte[] plainText) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        byte[] cipherText = cipher.doFinal(plainText);
        return cipherText;
    }

    /**
     * Decrypt a given input using an iv and a key.
     */
    static byte[] decrypt(byte[] iv, byte[] key, byte[] cipherText) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        byte[] plainText = cipher.doFinal(cipherText);
        return plainText;
    }

    /**
     * Generate an IV.
     */
    static byte[] generateIV() {
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[IV_LENGTH];
        random.nextBytes(iv);
        return iv;
    }
}
