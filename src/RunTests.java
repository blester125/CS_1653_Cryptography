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

import java.security.Security;
import java.util.Scanner;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class RunTests {

	protected static GroupClient groupC;
	protected static FileClient fileC;

	public static String groupIPAddr = "localhost";
	public static int groupPort = 8080;

	public static String fileIPAddr = "localhost";
	public static int filePort = 8081;

	public static String username = "test";
	public static String publicPath = "adminpublic.key";
	public static String privatePath = "adminprivate.key";

	public static void main (String[] args) throws Exception {

		Security.addProvider(new BouncyCastleProvider());

		Scanner console = new Scanner(System.in);

		groupC = new GroupClient();
		fileC = new FileClient();

		//Attempt to connect and authenticate with group server
		if(!groupC.connect(groupIPAddr, groupPort)){
			System.out.println("Connection to group server failed.");
			return;
		} else {
			int result = groupC.authenticateGroupServerRSA(username, publicPath, privatePath);

			if(result == -1){
				System.out.println("Could not authenticate with group server via RSA.");
				groupC.disconnect();
				return;
			}
		}


		//Attempt to connect to file server and authenticate
		// if(!fileC.connect(fileIPAddr, filePort)){
		// 	System.out.println("Connection to file server failed.");
		// 	return;
		// } else {
		// 	int result = fileC.authenticateFileServerRSA(publicPath, privatePath);

		// 	if(result == -1){
		// 		System.out.println("Cached File Server RSA public key was null or mismatched:");

		// 		String cached = RSA.generateFingerprints(fileC.cachedPublicKey);
		// 		String server = RSA.generateFingerprints(fileC.serverPublicKey);
				
		// 		System.out.println("Hostname:Port - " + fileC.sock.getInetAddress().getHostName() + ":" + Integer.toString(fileC.sock.getPort()));
		// 		System.out.println("Expected Key: " + cached);
		// 		System.out.println("Received Key: " + server);

		// 		System.out.println("\nAccept this connection? (y/n): ");

		// 		String connectionPrompt = console.next();

		// 		if(connectionPrompt.equals("y")){
		// 			System.out.println("Adding server to registry...");
		// 			fileC.addServerToRegistry(new ServerInfo(fileC.sock), fileC.serverPublicKey);
		// 			if(fileC.signedDiffieHellman(publicPath, privatePath) == null){
		// 				System.out.println("Server challenge failure.");
		// 				fileC.disconnect();
		// 				return;
		// 			}
		// 		} else {
		// 			System.out.println("Connection aborted by user");
		// 			fileC.disconnect();
		// 			return;
		// 		}
		// 	}
		// }

		//Attempt to get a token with a purposely botched sequence number
		UserToken wrongToken = groupC.wrongSequenceToken(username, groupC.getGroupServerKey());

		if(wrongToken == null)
			System.out.println("Token was correctly rejected by server (null was returned).\n\n\n\n\n");


		System.out.println(groupC.getGroupServerKey());

		//Get an actual token
		UserToken currToken = groupC.getToken(username, groupC.getGroupServerKey());

		System.out.println("\n\n\n\n\n\n");

		if (groupC.createUser("carol", "carolpublic.key", currToken) == 0) {
			System.out.println("User carol could not be created.");
			return;
		}
	}
}