
import java.awt.EventQueue;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.awt.Component;
import javax.swing.SwingUtilities;


public class RunClient {

	protected static GroupClient groupC;
	protected static FileClient fileC;
	protected static UserToken uToken;

	public static void main (String[] args){

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
							System.exit(0);
					}});
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}
}