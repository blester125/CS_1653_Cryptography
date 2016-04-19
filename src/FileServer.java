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
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;
import javax.crypto.SecretKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.apache.commons.codec.binary.Base64;

/* FileServer loads files from FileList.bin.  
   Stores files in shared_files directory. */
public class FileServer extends Server {
	
	public static final int SERVER_PORT = 4321;

	public static FileList fileList;

	static final int RSA_BIT_KEYSIZE = 2048;
	public static KeyPair rsaPair;
	public PrivateKey inputPrivate;
	public static SecretKey convertPrivate;

	private String fileServerPublicPath = "fileserverpublic.key";
	private String fileServerPrivatePath = "fileserverprivate.key";
	
	public FileServer() {
		super(SERVER_PORT, "FilePile");
	}

	public FileServer(int _port) {
		super(_port, "FilePile");
	}
	
	public void start() {
		Security.addProvider(new BouncyCastleProvider());

		String fileFile = "FileList.bin";

		Scanner console = new Scanner(System.in);
		String publicKeyPath = "";
		String privateKeyPath = "";
		ObjectInputStream fileStream;
		
		//This runs a thread that saves the lists on program exit
		Runtime runtime = Runtime.getRuntime();
		Thread catchExit = new Thread(new ShutDownListenerFS());
		runtime.addShutdownHook(catchExit);

		System.out.println("Enter Starter's public key path: ");
		publicKeyPath = console.next();
		System.out.println("Enter Starter's private key in Base64 encoding: ");
		privateKeyPath = console.next();

		//Get private key from string
		try {
			byte[] privateBytes = Base64.decodeBase64(privateKeyPath.getBytes("utf-8"));
			PKCS8EncodedKeySpec inputPrivateSpec = new PKCS8EncodedKeySpec(privateBytes);
			KeyFactory privateFactory = KeyFactory.getInstance("RSA", "BC");
			inputPrivate = privateFactory.generatePrivate(inputPrivateSpec);
			convertPrivate = KeyBox.convertPrivateKey(inputPrivate);
		} catch(Exception e){
			e.printStackTrace();
			System.exit(0);
		}

		KeyPair starterKeyPair = RSA.loadRSA(publicKeyPath, inputPrivate);

		//NEED TO DECRYPT AND LOAD SERVER PRIVATE KEY (USING ADMIN KEYPAIR)
		rsaPair = RSA.loadRSA(fileServerPublicPath, fileServerPrivatePath, convertPrivate);
		
		//Open user file to get user list
		try
		{
			FileInputStream fis = new FileInputStream(fileFile);
			fileStream = new ObjectInputStream(fis);
			Envelope tempEnv = (Envelope)fileStream.readObject();
			fileList = (FileList)Envelope.extractInner(tempEnv, convertPrivate).getObjContents().get(0);
		}
		catch(FileNotFoundException e)
		{
			System.out.println("FileList Does Not Exist. Creating FileList...");
			
			fileList = new FileList();
			
		}
		catch(IOException e)
		{
			System.out.println("Error reading from FileList file");
			System.exit(-1);
		}
		catch(ClassNotFoundException e)
		{
			System.out.println("Error reading from FileList file");
			System.exit(-1);
		}
		
		File file = new File("shared_files");
		if (file.mkdir()) {
			System.out.println("Created new shared_files directory");
		}
		else if (file.exists()){
			System.out.println("Found shared_files directory");
		}
		else {
			System.out.println("Error creating shared_files directory");				 
		}

		//Autosave Daemon. Saves lists every 5 minutes
		AutoSaveFS aSave = new AutoSaveFS();
		aSave.setDaemon(true);
		aSave.start();
		
		boolean running = true;
		
		try
		{			
			final ServerSocket serverSock = new ServerSocket(port);
			System.out.printf("%s up and running\n", this.getClass().getName());
			
			Socket sock = null;
			Thread thread = null;
			
			while(running)
			{
				sock = serverSock.accept();
				thread = new FileThread(sock, rsaPair);
				thread.start();
			}
			
			System.out.printf("%s shut down\n", this.getClass().getName());
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
}

//This thread saves user and group lists
class ShutDownListenerFS implements Runnable
{
	public void run()
	{
		System.out.println("Shutting down server");
		ObjectOutputStream outStream;

		Envelope fileListEnv = new Envelope("FileList");
		fileListEnv.addObject(FileServer.fileList);
		Envelope superFileListEnv = Envelope.buildSuper(fileListEnv, FileServer.convertPrivate);
		try
		{
			outStream = new ObjectOutputStream(new FileOutputStream("FileList.bin"));
			outStream.writeObject(superFileListEnv);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
}

class AutoSaveFS extends Thread
{
	public void run()
	{
		do
		{
			try
			{
				Thread.sleep(300000); //Save group and user lists every 5 minutes
				System.out.println("Autosave file list...");
				ObjectOutputStream outStream;

				Envelope fileListEnv = new Envelope("FileList");
				fileListEnv.addObject(FileServer.fileList);
				Envelope superFileListEnv = Envelope.buildSuper(fileListEnv, FileServer.convertPrivate);
				try
				{
					outStream = new ObjectOutputStream(new FileOutputStream("FileList.bin"));
					outStream.writeObject(superFileListEnv);
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
		}while(true);
	}
}
