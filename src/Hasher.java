import java.security.MessageDigest;
import java.security.Security;
import javax.crypto.Mac;

import javax.crypto.KeyAgreement;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import java.security.Key;
import java.security.PublicKey;
import java.security.KeyPair;
import java.security.*;

import java.io.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import sun.misc.BASE64Encoder;

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

	public static void main(String args[]) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
		keyGen.initialize(2048);
		KeyPair keyPair = keyGen.generateKeyPair();
		System.out.println(keyPair.getPublic().toString());
		System.out.println(keyPair.getPublic().getEncoded());
	}
}
