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

		String hostname = args[0];
		int port = Integer.parseInt(args[1]);
		String publicKeyPath = args[2];
		String privateKeyPath = args[3];
		String username = args[4];

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
		groupC.connect(hostname, port);
		groupC.authenticateGroupServerRSA(hostname, port, username, publicKeyPath, privateKeyPath);
		UserToken t = groupC.getToken(username, serverPublicKey);
		groupC.createGroup(username, t);
		groupC.disconnect();
		System.out.println("Connection, Login, Create Group, and Logout took: " 
							+ (System.currentTimeMillis() - start)
							+ " milliseconds");
	}
}
