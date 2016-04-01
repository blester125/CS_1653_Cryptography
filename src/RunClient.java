
import java.awt.EventQueue;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.lang.reflect.Field;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class RunClient {

	protected static GroupClient groupC;
	protected static FileClient fileC;
	protected static UserToken uToken;

	public static void main (String[] args) throws Exception {

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

		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					ClientApp window = new ClientApp();
					window.frmBrcSafeshare.setVisible(true);

					//Set up disconnect listener
					window.frmBrcSafeshare.addWindowListener(new WindowAdapter() {
						public void windowClosing(WindowEvent event) {
							groupC.disconnect();
							fileC.disconnect();
							System.exit(0);
					}});
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}
}