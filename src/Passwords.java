import java.math.BigInteger;
import java.security.*;

public class Passwords {
	public static BigInteger generateSalt() {
		return new BigInteger(256, new SecureRandom());
	}

	public static byte[] generatePasswordHash(String password, BigInteger salt) {
		String hashword = password + new String(salt.toByteArray());
		return Hasher.hash(hashword);
	}
}