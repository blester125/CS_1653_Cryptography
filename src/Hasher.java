import java.security.MessageDigest;
import java.security.Security;
import javax.crypto.Mac;

import javax.crypto.KeyAgreement;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import java.security.Key;

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

	public static byte[] generateHMAC(Key k, Object obj) {
		try {		
			Mac mac = Mac.getInstance("HmacSHA256", "BC");
			mac.init(k);
			byte[] raw = mac.doFinal(obj.toString().getBytes("UTF-8"));
			return raw
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}	
	}

	public static boolean verifiyHash(byte[] revHash, Object obj) {
		byte[] madeHash = hash(obj);
		return MessageDigest.isEqual(revHash, madeHash);
	}

	public static boolean verifyHMAC(String revHMAC, Key k, Object obj) {
		String madeHMAC = generateHMAC(k, obj);
		return MessageDigest.isEqual(revHMAC.getBytes(), madeHMAC.getBytes());
	}

	public static void main(String args[]) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		Envelope test = new Envelope("Test");
		String testString = "TEST STRING";
		test.addObject(testString);
		Envelope test2 = new Envelope("Test");
		String testString2 = "TEST STRING";
		test2.addObject(testString2);
		String hash1 = new String(hash(test));
		String hash2 = new String(hash(test2));
		System.out.println(hash1 + "\n\n");
		System.out.println(hash2);
	}
}
