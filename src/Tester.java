public class Tester {
	
	public static void run() throws Exception {
		while (true) {
			RunClient.groupC.connect("localhost", 8080);
			RunClient.groupC.authenticateGroupServer("test", "test");
			Thread.sleep(10000L);
			RunClient.groupC.disconnect();
		}
	}
}