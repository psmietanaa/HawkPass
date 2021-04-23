import org.junit.Test;
import static org.junit.Assert.*;

import java.util.Arrays;

public class PasswordManagerTests {
    @Test
    public void testAESEncryption() throws Exception {
        byte[] iv = new byte[16];
        byte[] key = new byte[16];
        byte[] data = "data".getBytes();

        byte[] actual = AES.encrypt(iv, key, data);
        byte[] expected = {42, 124, 20, 127, -3, 71, -43, -93, 92, -39, -15, 30, -13, 62, -29, -22};

        assertArrayEquals(expected, actual);
    }

    @Test
    public void testAESDecryption() throws Exception {
        byte[] iv = new byte[16];
        byte[] key = new byte[16];
        byte[] data = {42, 124, 20, 127, -3, 71, -43, -93, 92, -39, -15, 30, -13, 62, -29, -22};

        String actual = new String(AES.decrypt(iv, key, data));
        String expected = "data";

        assertEquals(expected, actual);
    }

    @Test
    public void testHMACAuthentication() throws Exception {
        byte[] key = new byte[16];
        byte[] data = "data".getBytes();

        byte[] hmac1 = HMAC.generateHmac(key, data);
        byte[] hmac2 = HMAC.generateHmac(key, data);

        assertArrayEquals(hmac1, hmac2);
    }

    @Test
    public void testHMACIntegrity() throws Exception {
        byte[] key = new byte[16];
        byte[] data = "data".getBytes();

        byte[] hmac1 = HMAC.generateHmac(key, data);
        data = Utilities.addBytes(data, "more data".getBytes());
        byte[] hmac2 = HMAC.generateHmac(key, data);

        assertFalse(Arrays.equals(hmac1, hmac2));
    }

    @Test
    public void testPBKDF2Key() throws Exception {
        byte[] salt = new byte[64];
        byte[] password = "password".getBytes();

        byte[] actual = PBKDF2.generateKeyFromPassword(salt, password);

        assertEquals(32, actual.length);
   }

    @Test
    public void testPBKDF2Hash() throws Exception {
        byte[] salt = new byte[64];
        byte[] password = "password".getBytes();

        byte[] actual = PBKDF2.generateHashFromPassword(salt, password);

        assertEquals(64, actual.length);
    }

    @Test
    public void testGeneratePassword() {
        String randomPassword = GeneratePassword.generateRandomPassword();

        boolean hasLowercase = !randomPassword.equals(randomPassword.toUpperCase());
        assertTrue(hasLowercase);

        boolean hasUppercase = !randomPassword.equals(randomPassword.toLowerCase());
        assertTrue(hasUppercase);

        boolean hasDigit = !randomPassword.matches("[\\d]*");
        assertTrue(hasDigit);

        boolean hasSpecial = !randomPassword.matches("[\\w]*");
        assertTrue(hasSpecial);
    }

    @Test
    public void testRecord() {
        Record r1 = new Record("www.uiowa.edu", "hawkid", "password");
        Record r2 = new Record("www.uiowa.edu", "hawkid", "password");
        Record r3 = new Record("www.google.edu", "admin", "password");

        assertEquals(r1, r2);
        assertNotEquals(r1, r3);
    }
}
