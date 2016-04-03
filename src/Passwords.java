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

import java.math.BigInteger;
import java.security.*;

/*
 * This class is pointless now that we use RSA only
 */

public class Passwords {
  /**
   * Generate a random salt of 256 bits long
   * @return random salt of 256 bits long
   */
	public static BigInteger generateSalt() {
		return new BigInteger(256, new SecureRandom());
	}

  /**
   * Generate a hash of the password concatenated with the salt
   * @param password: The users password
   * @param salt: The salt for this user
   * @return The hash of the password plus the salt
   */
	public static byte[] generatePasswordHash(String password, BigInteger salt) {
		String hashword = password + new String(salt.toByteArray());
		return Hasher.hash(hashword);
	}
}