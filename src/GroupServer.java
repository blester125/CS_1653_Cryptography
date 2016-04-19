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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.Security;
import java.util.Scanner;
import javax.crypto.SecretKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.apache.commons.codec.binary.Base64;

/* Group server. Server loads the users from UserList.bin.
 * If user list does not exists, it creates a new list and 
 * makes the user the server administrator.
 * On exit, the server saves the user list to file.
 */
public class GroupServer extends Server {

	public static final int SERVER_PORT = 8765;
	public UserList userList;
	public GroupList groupList;
	static final int RSA_BIT_KEYSIZE = 2048;
	// Seems dangerous
	public KeyPair keyPair;
	private String groupServerPublicPath = "groupserverpublic.key";
	private String groupServerPrivatePath = "groupserverprivate.key";
	public PrivateKey inputPrivate;
	public static SecretKey convertPrivate;

	public GroupServer() {
		super(SERVER_PORT, "ALPHA");
	}

	public GroupServer(int _port) {
		super(_port, "ALPHA");
	}

	public void start() {
		Security.addProvider(new BouncyCastleProvider());
		// Overwrote server.start() because if no user file exists, initial admin account needs to be created
		String userFile = "UserList.bin";
		String groupFile = "GroupList.bin";
		Scanner console = new Scanner(System.in);
		ObjectInputStream userStream;
		ObjectInputStream groupStream;
		String username = "";
		String password = "nopassword";
		String publicKeyPath = "";
		String privateKeyPath = "";

		//This runs a thread that saves the lists on program exit
		Runtime runtime = Runtime.getRuntime();
		runtime.addShutdownHook(new ShutDownListener(this));

		System.out.println("Enter ADMIN's public key path: ");
		publicKeyPath = console.next();
		System.out.println("Enter ADMIN's private key in Base64 encoding: ");
		privateKeyPath = console.next();

		//Get private key from string
		try{
			byte[] privateBytes = Base64.decodeBase64(privateKeyPath.getBytes("utf-8"));
			PKCS8EncodedKeySpec inputPrivateSpec = new PKCS8EncodedKeySpec(privateBytes);
			KeyFactory privateFactory = KeyFactory.getInstance("RSA", "BC");
			inputPrivate = privateFactory.generatePrivate(inputPrivateSpec);
			convertPrivate = KeyBox.convertPrivateKey(inputPrivate);
		} catch(Exception e){
			e.printStackTrace();
			System.exit(0);
		}

		KeyPair adminKeyPair = RSA.loadRSA(publicKeyPath, inputPrivate);

		//NEED TO DECRYPT AND LOAD SERVER PRIVATE KEY (USING ADMIN KEYPAIR)
		keyPair = RSA.loadRSA(groupServerPublicPath, groupServerPrivatePath, convertPrivate);

		//Open user file to get user list
		try
		{
			FileInputStream fis = new FileInputStream(userFile);
			userStream = new ObjectInputStream(fis);
			Envelope tempEnv = (Envelope)userStream.readObject();
			userList = (UserList)Envelope.extractInner(tempEnv, convertPrivate).getObjContents().get(0);
		}
		catch(FileNotFoundException e)
		{
			System.out.println("UserList File Does Not Exist. Creating UserList...");
			System.out.println("No users currently exist. Your account will be the administrator.");
			System.out.println("Enter new username : ");
			username = console.next();

			//Create a new list, add current user to the ADMIN group. They now own the ADMIN group.
			userList = new UserList();
			userList.addUser(username);
			userList.addGroup(username, "ADMIN");
			userList.addOwnership(username, "ADMIN");
			//BigInteger salt = Passwords.generateSalt();
			//userList.setSalt(username, salt);
			//byte[] hashword = Passwords.generatePasswordHash(password, salt);
			//userList.setPassword(username, hashword);
			//userList.setNewPassword(username, false);
			userList.setPublicKey(username, adminKeyPair.getPublic());
		}
		catch(IOException e)
		{
			System.out.println("Error reading from UserList file");
			System.exit(-1);
		}
		catch(ClassNotFoundException e)
		{
			System.out.println("Error reading from UserList file");
			System.exit(-1);
		}

		//Open group file to get group list
		//self-implemented but cloned from above code
		try
		{
			FileInputStream fis2 = new FileInputStream(groupFile);
			groupStream = new ObjectInputStream(fis2);
			Envelope tempEnv2 = (Envelope)groupStream.readObject();
			groupList = (GroupList)Envelope.extractInner(tempEnv2, convertPrivate).getObjContents().get(0);
		}
		catch(FileNotFoundException e)
		{
			System.out.println("GroupList File Does Not Exist. Creating GroupList...");
			System.out.println("No groups currently exist. Your account will be the ADMIN.");
			
			//Create a new list, add current user to the ADMIN group. They now own the ADMIN group.
			groupList = new GroupList();
			groupList.createGroup("ADMIN", username);
			groupList.addMember("ADMIN", username);
			System.out.println("ADMIN group created.");
		}
		catch(IOException e)
		{
			System.out.println("Error reading from GroupList file");
			System.exit(-1);
		}
		catch(ClassNotFoundException e)
		{
			System.out.println("Error reading from GroupList file");
			System.exit(-1);
		}

		//Autosave Daemon. Saves lists every 5 minutes
		AutoSave aSave = new AutoSave(this);
		aSave.setDaemon(true);
		aSave.start();

		//Begin
		System.out.println("Begin serving...\n\n");

		//This block listens for connections and creates threads on new connections
		try
		{

			final ServerSocket serverSock = new ServerSocket(port);

			Socket sock = null;
			GroupThread thread = null;

			while(true)
			{
				sock = serverSock.accept();
				thread = new GroupThread(sock, this);
				thread.start();
			}
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
}

//This thread saves the user list
class ShutDownListener extends Thread
{
	public GroupServer my_gs;

	public ShutDownListener (GroupServer _gs) {
		my_gs = _gs;
	}

	public void run()
	{
		System.out.println("Shutting down server");
		ObjectOutputStream outStream;

		Envelope userListEnv = new Envelope("UserList");
		userListEnv.addObject(my_gs.userList);
		Envelope groupListEnv = new Envelope("GroupList");
		groupListEnv.addObject(my_gs.groupList);
		Envelope superUserListEnv = Envelope.buildSuper(userListEnv, my_gs.convertPrivate);
		Envelope superGroupListEnv = Envelope.buildSuper(groupListEnv, my_gs.convertPrivate);
		try
		{
			outStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
			outStream.writeObject(superUserListEnv);
			outStream = new ObjectOutputStream(new FileOutputStream("GroupList.bin"));
			outStream.writeObject(superGroupListEnv);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
}

class AutoSave extends Thread
{
	public GroupServer my_gs;

	public AutoSave (GroupServer _gs) {
		my_gs = _gs;
	}

	public void run()
	{
		do
		{
			try
			{
				Thread.sleep(300000); //Save group and user lists every 5 minutes
				System.out.println("Autosave group and user lists...");
				ObjectOutputStream outStream;

				Envelope userListEnv = new Envelope("UserList");
				userListEnv.addObject(my_gs.userList);
				Envelope groupListEnv = new Envelope("GroupList");
				groupListEnv.addObject(my_gs.groupList);
				Envelope superUserListEnv = Envelope.buildSuper(userListEnv, my_gs.convertPrivate);
				Envelope superGroupListEnv = Envelope.buildSuper(groupListEnv, my_gs.convertPrivate);
				try
				{
					outStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
					outStream.writeObject(superUserListEnv);
					outStream = new ObjectOutputStream(new FileOutputStream("GroupList.bin"));
					outStream.writeObject(superGroupListEnv);
				}
				catch(Exception e)
				{
					System.err.println("Error: " + e.getMessage());
					e.printStackTrace(System.err);
				}

			}
			catch(Exception e)
			{
				System.out.println("Autosave Interrupted");
			}
		} while(true);
	}
}
