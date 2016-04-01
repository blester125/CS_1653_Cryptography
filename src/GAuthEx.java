import java.util.Random;
import java.util.*;
import java.io.*;
import java.security.*;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Mac;
import java.util.concurrent.TimeUnit;
import org.apache.commons.codec.binary.Base32;

public class GAuthEx {

	public static void main(String main[]) throws Exception {
		//System.out.println("Use this key with Google Authenticator.");
		//String key = generateKey();
		//System.out.println(key);
		BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
    System.out.print("Enter you key: ");
    String key = in.readLine();
		// Check codes.
		while (true) {
			long t = new Date().getTime() / TimeUnit.SECONDS.toMillis(30);
			System.out.print("Enter code: ");
			String code = in.readLine();
			long c = Integer.parseInt(code);
			System.out.println("Code was: " + check_code(key, c, t));
		}
	}

	public static String generateKey() {
		int secretSize = 10;
		byte[] buffer = new byte[32];
		new Random().nextBytes(buffer);
		Base32 codec = new Base32();
		byte[] secretKey = Arrays.copyOf(buffer, secretSize);
		byte[] bEncodedKey = codec.encode(secretKey);
		return new String(bEncodedKey);
	}

  public static long getT() {
    return new Date().getTime() / TimeUnit.SECONDS.toMillis(30);
  }

	public static boolean check_code(
  String secret,
  long code,
  long t)
    throws NoSuchAlgorithmException,
      InvalidKeyException {
  Base32 codec = new Base32();
  byte[] decodedKey = codec.decode(secret);

  // Window is used to check codes generated in the near past.
  // You can use this value to tune how far you're willing to go. 
  int window = 0;
  for (int i = -window; i <= window; ++i) {
    long hash = verify_code(decodedKey, t + i);

    if (hash == code) {
      return true;
    }
  }

  // The validation code is invalid.
  return false;
}

private static int verify_code(
  byte[] key,
  long t)
  throws NoSuchAlgorithmException,
    InvalidKeyException {
  byte[] data = new byte[8];
  long value = t;
  for (int i = 8; i-- > 0; value >>>= 8) {
    data[i] = (byte) value;
  }

  SecretKeySpec signKey = new SecretKeySpec(key, "HmacSHA1");
  Mac mac = Mac.getInstance("HmacSHA1");
  mac.init(signKey);
  byte[] hash = mac.doFinal(data);

  int offset = hash[20 - 1] & 0xF;
  
  // We're using a long because Java hasn't got unsigned int.
  long truncatedHash = 0;
  for (int i = 0; i < 4; ++i) {
    truncatedHash <<= 8;
    // We are dealing with signed bytes:
    // we just keep the first byte.
    truncatedHash |= (hash[offset + i] & 0xFF);
  }

  truncatedHash &= 0x7FFFFFFF;
  truncatedHash %= 1000000;

  return (int) truncatedHash;
}
}