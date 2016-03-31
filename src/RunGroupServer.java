/* Driver program for FileSharing Group Server */
import java.security.*;
import java.lang.reflect.Field;


public class RunGroupServer {
	
	public static void main(String[] args) {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		try {
	        Field field = Class.forName("javax.crypto.JceSecurity").getDeclaredField("isRestricted");
	        field.setAccessible(true);
	        field.set(null, java.lang.Boolean.FALSE);
	    } catch (Exception ex) {
	    	ex.printStackTrace();
	    }
		if (args.length> 0) {
			try {
				GroupServer server = new GroupServer(Integer.parseInt(args[0]));
				server.start();
			}
			catch (NumberFormatException e) {
				System.out.printf("Enter a valid port number or pass no arguments to use the default port (%d)\n", GroupServer.SERVER_PORT);
			}
		}
		else {
			GroupServer server = new GroupServer();
			server.start();
		}
	}
}
