
import java.awt.EventQueue;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class RunClient {

	protected static GroupClient groupC;
	protected static FileClient fileC;
	protected static UserToken uToken;

	public static void main (String[] args) throws Exception {

		Security.addProvider(new BouncyCastleProvider());

		groupC = new GroupClient();
		fileC = new FileClient();

		if (args.length == 1) {
			Tester.run();
		} else {

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
}