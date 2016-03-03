/* FileServer loads files from FileList.bin.  Stores files in shared_files directory. */

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;

import java.security.Security;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.KeyFactory;

import java.security.spec.X509EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class FileServer extends Server {
	
	public static final int SERVER_PORT = 4321;

	public static FileList fileList;

	static final int RSA_BIT_KEYSIZE = 2048;
	public static KeyPair rsaPair;
	
	
	public FileServer() {
		super(SERVER_PORT, "FilePile");
	}

	public FileServer(int _port) {
		super(_port, "FilePile");
	}
	
	public void start() {
		Security.addProvider(new BouncyCastleProvider());

		String fileFile = "FileList.bin";
		ObjectInputStream fileStream;
		
		//This runs a thread that saves the lists on program exit
		Runtime runtime = Runtime.getRuntime();
		Thread catchExit = new Thread(new ShutDownListenerFS());
		runtime.addShutdownHook(catchExit);
		
		//Open user file to get user list
		try
		{
			FileInputStream fis = new FileInputStream(fileFile);
			fileStream = new ObjectInputStream(fis);
			fileList = (FileList)fileStream.readObject();
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


		//Attempt to load RSA key pair from file
		try{
			File fsPublicKey = new File("fspublic.key");
			FileInputStream keyIn = new FileInputStream("fspublic.key");
			byte[] encPublicKey = new byte[(int) fsPublicKey.length()];
			keyIn.read(encPublicKey);
			keyIn.close();

			File fsPrivateKey = new File("fsprivate.key");
			keyIn = new FileInputStream("fsprivate.key");
			byte[] encPrivateKey = new byte[(int) fsPrivateKey.length()];
			keyIn.read(encPrivateKey);
			keyIn.close();

			KeyFactory kf = KeyFactory.getInstance("RSA", "BC");
			X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encPublicKey);
			PublicKey publicKey = kf.generatePublic(publicKeySpec);

			PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encPrivateKey);
			PrivateKey privateKey = kf.generatePrivate(privateKeySpec);

			rsaPair = new KeyPair(publicKey, privateKey);

			System.out.println("Found RSA key pair. Loaded successfully!");
		}
		catch (FileNotFoundException e) {

			try{
				System.out.println("Did not find public and/or private RSA keys. Generating new key pair....");
			
				//Generate RSA key pair with KeyPairGenerator, 1024 bits
				KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
				keyGen.initialize(RSA_BIT_KEYSIZE);
				rsaPair = keyGen.generateKeyPair();
				PrivateKey privateKey = rsaPair.getPrivate();
				PublicKey publicKey = rsaPair.getPublic();

				//Store both keys to file
				X509EncodedKeySpec x590keyspec = new X509EncodedKeySpec(publicKey.getEncoded());
				FileOutputStream keyOut = new FileOutputStream("fspublic.key");
				keyOut.write(x590keyspec.getEncoded());
				keyOut.close();

				PKCS8EncodedKeySpec pkcs8keyspec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
				keyOut = new FileOutputStream("fsprivate.key");
				keyOut.write(pkcs8keyspec.getEncoded());
				keyOut.close();

				System.out.println("New RSA key pair generated and stored!");
			}
			catch (Exception f){
				System.out.println("Exception thrown in create new RSA pair.");
				System.exit(-1);
			}

		}
		catch (IOException e) {
			System.out.println("Could not read or write from/to key files!");
			System.exit(-1);
		}
		catch (NoSuchAlgorithmException e){
			System.out.println("Algorithm does not exist!");
			System.exit(-1);
		}
		catch (InvalidKeySpecException e){
			System.out.println("Invalid key specification!");
			System.exit(-1);
		}
		catch (Exception e){
			System.out.println("unspecified exception thrown");
			System.exit(-1);
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
				thread = new FileThread(sock);
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

		try
		{
			outStream = new ObjectOutputStream(new FileOutputStream("FileList.bin"));
			outStream.writeObject(FileServer.fileList);
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
				try
				{
					outStream = new ObjectOutputStream(new FileOutputStream("FileList.bin"));
					outStream.writeObject(FileServer.fileList);
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
