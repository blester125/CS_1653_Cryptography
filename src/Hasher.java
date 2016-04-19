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

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Security;
import java.util.Arrays;

import javax.crypto.Mac;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Hasher {
	public static byte[] hash(Object obj) {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256", "BC");
			md.update(obj.toString().getBytes("UTF-8"));
			return md.digest();
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	
	public static byte[] hash(byte[] arr) {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256", "BC");
			md.update(arr);
			return md.digest();
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	public static byte[] generateHMAC(Key k, byte[] obj) {
		try {		
			Mac mac = Mac.getInstance("HmacSHA256", "BC");
			mac.init(k);
			byte[] raw = mac.doFinal(obj);
			return raw;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}	
	}
	
	

	public static boolean verifyHash(byte[] recvHash, Object obj) {
		byte[] madeHash = hash(obj);
		return MessageDigest.isEqual(recvHash, madeHash);
	}

	public static boolean verifyHMAC(byte[] recvHMAC, byte[] madeHMAC) {
		return MessageDigest.isEqual(recvHMAC, madeHMAC);
	}

	public static byte[] convertToByteArray(Object object) {
		try 
			(ByteArrayOutputStream bos = new ByteArrayOutputStream();
			ObjectOutput out = new ObjectOutputStream(bos)) 
		{
			out.writeObject(object);
			return bos.toByteArray();
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	public static byte[] concatenateArrays(byte[] arr1, byte[] arr2) {
		byte[] arr3 = new byte[arr1.length + arr2.length];
		for (int i = 0; i < arr1.length; i++) {
			arr3[i] = arr1[i];
		}
		for (int i = 0; i < arr2.length; i++) {
			arr3[i + arr1.length] = arr2[i];
		}
		return arr3;
	}

	public static void main(String args[]) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
		keyGen.initialize(2048);
		KeyPair keyPair = keyGen.generateKeyPair();
		System.out.println(keyPair.getPublic().toString());
		System.out.println(keyPair.getPublic().getEncoded());
	}
}
