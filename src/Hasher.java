import java.security.MessageDigest;
import java.security.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.math.BigInteger;

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
