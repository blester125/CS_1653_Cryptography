import java.io.IOException;
import java.io.Serializable;
import java.security.Key;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SealedObject;


public class CipherBox{
	/**
	 * encrypts the given plaintext with the key provided
	 * @param plainText	object to be encrypted
	 * @param key	key to use for encryption
	 * @param cipher	cipher used for encryption
	 * @return	encrypted object
	 */
	public static SealedObject encrypt(Serializable plainText, Cipher cipher) {
		try {
			return new SealedObject(plainText, cipher);
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	/**
	 * decrypts the "encrypted" with the key
	 * @param encrypted	encrypted object
	 * @param key	key to decrypt with
	 * @cipher	cipher used for decryption
	 * @return	decrypted object
	 */
	public static Object decrypt(SealedObject encrypted, Cipher cipher) {
		try {
			return (Object)encrypted.getObject(cipher);
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
}
