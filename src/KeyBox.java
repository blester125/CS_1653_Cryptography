import java.io.IOException;
import java.io.Serializable;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class KeyBox {

	private static int size = 128;
	private static String algo = "AES";

	public static SecretKey generateKey() {
		try {
			KeyGenerator keyGenerator = KeyGenerator.getInstance(algo);
			keyGenerator.init(size);
			return keyGenerator.generateKey();
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * evolves the key by hashing it a given amount of times
	 * @param key
	 * @param repeat
	 * @return	null on failure
	 */
	public static SecretKey evolveKey(SecretKey key, int repeat) {
		try {
			byte[] keyBytes = key.getEncoded();
			for (int i = 0; i < repeat; i++) {
				keyBytes = Hasher.hash(keyBytes);
			}
			return new SecretKeySpec(keyBytes, 0, 16, "AES");
		} catch(Exception e) {
			e.printStackTrace();
			return null;
		}
	}
}
