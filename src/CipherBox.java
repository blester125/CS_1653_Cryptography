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

import java.io.IOException;
import java.io.Serializable;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SealedObject;
import javax.crypto.spec.IvParameterSpec;

import org.apache.commons.codec.binary.Base64;


public class CipherBox {
	// ciphers for AES and RSA encryption and decryption
	private static Cipher AESCipherEncrypt;
	private static Cipher AESCipherDecrypt;
	private static Cipher RSACipherEncrypt;
	private static Cipher RSACipherDecrypt; 
	
	/**
	 * generates a random IV
	 * @return returns a random IVParameterSpec 
	 */
	public static IvParameterSpec generateRandomIV() {
		SecureRandom rnd = new SecureRandom();
		byte iv[] = new byte[16];
		rnd.nextBytes(iv);
		return new IvParameterSpec(iv);
	}
	
	/**
	 * encrypts the given serializable object with the key and IV
	 * using symmetric key encryption
	 * @param plainText
	 * @param key
	 * @param iv initialization vector
	 * @return	the encrypted object, null on failure
	 */
	public static SealedObject encrypt(Serializable plainText, Key key, IvParameterSpec iv) {
		try {
			AESCipherEncrypt = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
			AESCipherEncrypt.init(Cipher.ENCRYPT_MODE, key, iv);
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
		try {
			return new SealedObject(plainText, AESCipherEncrypt);
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	/**
	 * decrypts the given object with the key and IV
	 * @param encrypted	encrypted object
	 * @param key
	 * @param iv	initialization vector
	 * @return	decrypted object
	 */
	public static Object decrypt(SealedObject encrypted, Key key, IvParameterSpec iv) {
		try {
			AESCipherDecrypt = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
			AESCipherDecrypt.init(Cipher.DECRYPT_MODE, key, iv);
		} catch (InvalidKeyException e1) {
			e1.printStackTrace();
		} catch (Exception e1) {
			e1.printStackTrace();
		}
		
		try {
			return (Object)encrypted.getObject(AESCipherDecrypt);
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	/**
	 * encrypts the given plaintext with the key provided
	 * which is a member of an RSA pair
	 * @param plainText	object to be encrypted
	 * @param key	key to use for encryption
	 * @return	encrypted object
	 */
	public static SealedObject encrypt(Serializable plainText, Key key) {
		try {
			RSACipherEncrypt = Cipher.getInstance("RSA", "BC");
			RSACipherEncrypt.init(Cipher.ENCRYPT_MODE, key);
		} catch (Exception e) {
			e.printStackTrace();
		}
		try {
			return new SealedObject(plainText, RSACipherEncrypt);
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	/**
	 * decrypts the "encrypted" with the key
	 * which is a member of an RSA pair
	 * @param encrypted	encrypted object
	 * @param key	key to decrypt with
	 * @return	decrypted object
	 */
	public static Object decrypt(SealedObject encrypted, Key key) {
		try {
			RSACipherDecrypt = Cipher.getInstance("RSA", "BC");
			RSACipherDecrypt.init(Cipher.DECRYPT_MODE, key);
		} catch (Exception e) {
			e.printStackTrace();
		}
		try {
			return (Object)encrypted.getObject(RSACipherDecrypt);
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	// public static String getKeyAsString(Key key) {
	// 	return new String(Base64.encodeBase64(key.getEncoded())); 
	// }
	
	public static Cipher initializeEncryptCipher(Key key, IvParameterSpec iv) {
		try {
			AESCipherEncrypt = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
			AESCipherEncrypt.init(Cipher.ENCRYPT_MODE, key, iv);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
		
		return AESCipherEncrypt;
	}
	
	public static Cipher initializeDecryptCipher(Key key, IvParameterSpec iv) {
		try {
			AESCipherDecrypt = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
			AESCipherDecrypt.init(Cipher.DECRYPT_MODE, key, iv);
		} catch(Exception e) {
			e.printStackTrace();
			return null;
		}
		
		return AESCipherDecrypt;
	}
}
