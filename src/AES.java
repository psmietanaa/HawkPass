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
    // AES has 128 block size
    protected static final int IV_LENGTH = 16;

    // Length of the key in bits
    protected static final int KEY_LENGTH = 256;

    // Version of the encryption algorithm
    protected static final String AES_ALGORITHM = "AES/CBC/PKCS5Padding";

    /**
     * Encrypt a given input using an iv and a key.
     */
    protected static byte[] encrypt(byte[] iv, byte[] key, byte[] plainText) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        byte[] cipherText = cipher.doFinal(plainText);
        return cipherText;
    }

    /**
     * Decrypt a given input using an iv and a key.
     */
    protected static byte[] decrypt(byte[] iv, byte[] key, byte[] cipherText) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        byte[] plainText = cipher.doFinal(cipherText);
        return plainText;
    }

    /**
     * Generate an IV.
     */
    protected static byte[] generateIV() {
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[IV_LENGTH];
        random.nextBytes(iv);
        return iv;
    }
}
