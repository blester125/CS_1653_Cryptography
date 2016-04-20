/************************************
 * CS 1653 Term Project at the      *
 * University of Pittsburgh         *
 * Taught by Bill Garrison          *
 * Spring 2016                      *
 * By:                              *
 *   Brian Lester                   *
 *   Ryan Conley                    *
 *   Carmen Condeluci               *
 ************************************/

import java.security.Key;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.PrivateKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

public class KeyBox {

	private static int size = 256;
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

	public static SecretKey convertPrivateKey(PrivateKey inputKey){

		String temp = getKeyAsString(inputKey);
		byte[] hash = Hasher.hash(temp);

		SecretKey key = new SecretKeySpec(hash, 0, hash.length, "AES");

		return key;
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

	public static boolean compareKey(Key keyOne, Key keyTwo){

		if(keyOne.equals(keyTwo))
			return true;
		
		return false;
	}

	public static SecretKey generateConfidentialityKey(SecretKey inputKey){

		String temp = getKeyAsString(inputKey) + "Confidentiality";
		byte[] hash = Hasher.hash(temp);

		SecretKey key = new SecretKeySpec(hash, 0, hash.length, "AES");

		return key;
	}

	public static SecretKey generateIntegrityKey(SecretKey inputKey){

		String temp = getKeyAsString(inputKey) + "Integrity";
		byte[] hash = Hasher.hash(temp);

		SecretKey key = new SecretKeySpec(hash, 0, hash.length, "AES");

		return key;
	}

	public static String getKeyAsString(Key key) {
		return new String(Base64.encodeBase64(key.getEncoded())); 
	}
}
