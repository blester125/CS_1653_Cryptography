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

import java.lang.reflect.Field;
import java.security.Security;
import java.security.PublicKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class BenchMark {

	protected static GroupClient groupC;
	protected static FileClient fileC;

	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		try {
			Field field = Class.forName("javax.crypto.JceSecurity").getDeclaredField("isRestricted");
			field.setAccessible(true);
			field.set(null, java.lang.Boolean.FALSE);
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		groupC = new GroupClient();
		fileC = new FileClient();
		PublicKey serverPublicKey = RSA.loadServerKey("groupserverpublic.key");
		long start = System.currentTimeMillis();
		groupC.connect("192.168.1.219", 8080);
		groupC.authenticateGroupServerRSA("localhost", 8080, "test", "adminpublic.key", "adminprivate.key");
		UserToken t = groupC.getToken("test", serverPublicKey);
		groupC.createGroup("test", t);
		groupC.disconnect();
		System.out.println("Connection, Login, Create Group, and Logout took: " 
							+ (System.currentTimeMillis() - start)
							+ " milliseconds");
	}
}
