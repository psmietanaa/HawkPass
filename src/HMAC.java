import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * This class is responsible for generating HMAC-SHA512.
 * Based on https://www.novixys.com/blog/hmac-sha256-message-authentication-mac-java
 */
public class HMAC {
    // Length of HMAC in bytes
    static final int HMAC_LENGTH = 64;

    // Version of the HMAC algorithm
    static final String HMAC_ALGORITHM = "HmacSHA512";

    /**
     * Generate HMAC from a key and given input.
     */
    static byte[] generateHmac(byte[] key, byte[] input) throws Exception {
        Mac hmac = Mac.getInstance(HMAC_ALGORITHM);
        hmac.init(new SecretKeySpec(key, HMAC_ALGORITHM));
        return hmac.doFinal(input);
    }
}
