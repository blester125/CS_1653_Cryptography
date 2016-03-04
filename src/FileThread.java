/* File worker thread handles the business of uploading, downloading, and removing files for clients with valid tokens */

import java.lang.Thread;
import java.net.Socket;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import java.security.KeyPair;

import java.security.SecureRandom;
import javax.crypto.spec.IvParameterSpec;

import javax.crypto.SealedObject;
import java.math.BigInteger;

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
import java.security.MessageDigest;

import java.security.spec.X509EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;

public class FileThread extends Thread
{
	private final Socket socket;
	private boolean isSecureConnection;
	private boolean isAuthenticated;
	private SecretKey secretKey;
	private KeyPair rsaPair;
	// Group Server Publi Key
	public PublicKey serverPublicKey = null;

	public FileThread(Socket _socket, KeyPair _rsaPair)
	{
		socket = _socket;
		rsaPair = _rsaPair;
		isSecureConnection = false;
		isAuthenticated = false;
		
	}

	public Envelope buildSuper(Envelope env){

		IvParameterSpec ivspec = CipherBox.generateRandomIV();			
		Envelope superEnv = new Envelope("SUPER");
		superEnv.addObject(CipherBox.encrypt(env, secretKey, ivspec));
		superEnv.addObject(ivspec.getIV());

		return superEnv;
	}

	public Envelope extractInner(Envelope superInputEnv){

		SealedObject innerEnv = (SealedObject)superInputEnv.getObjContents().get(0);
		IvParameterSpec decIVSpec = new IvParameterSpec((byte[])superInputEnv.getObjContents().get(1));
		Envelope env = (Envelope)CipherBox.decrypt(innerEnv, secretKey, decIVSpec);

		return env;
	}

	public void run()
	{
		boolean proceed = true;
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

		try
		{
			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
			final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
			final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
			Envelope response;

			do
			{
				Envelope e;

				if(!isSecureConnection) {
					e = (Envelope)input.readObject();
				}
				else {
					e = extractInner((Envelope)input.readObject());
				}

				System.out.println("Request received: " + e.getMessage());

				// Client wishes to establish a shared symmetric secret key
				if(e.getMessage().equals("SESSIONKEY")) {

					// Retrieve Client's public key
					PublicKey clientPK = (PublicKey)e.getObjContents().get(0);
					KeyPair keypair = null;
					KeyAgreement keyAgreement = null;

					// generate secret key and send back public key
					try {

						keypair = DiffieHellman.genKeyPair();
						keyAgreement = DiffieHellman.genKeyAgreement(keypair);
						secretKey = DiffieHellman.generateSecretKey(clientPK, keyAgreement);
						System.out.println(secretKey.getEncoded());

						response = new Envelope("OK");
						response.addObject(keypair.getPublic());
						response.addObject(rsaPair.getPublic());
						output.writeObject(response);
						isSecureConnection = true;
						System.out.println("Client and server set up secure communication via DH.");
					} catch(Exception exception) {
						exception.printStackTrace();
						response = new Envelope("FAIL");
						response.addObject(response);
						output.writeObject(response);
					}
				}
				// Client sends server the challenge, server will decrypt and respond
				else if(e.getMessage().equals("CHALLENGE") && isSecureConnection){

					try {
						//Recover sealedobject of challenge from envelope, then decrypt
						SealedObject encRSA_R1 = (SealedObject)e.getObjContents().get(0);
						BigInteger r1 = (BigInteger)CipherBox.decrypt(encRSA_R1, rsaPair.getPrivate());

						//build envelope
						response = new Envelope("CH_RESPONSE");
						response.addObject(r1);

						//send it back
						output.writeObject(buildSuper(response));
						System.out.println("SENT from CHALLENGE: " + response);
					} catch (Exception exception) {

						exception.printStackTrace();
						response = new Envelope("FAIL");
						response.addObject(response);
						output.writeObject(buildSuper(response));
					}

				}
				// If successful, set your flag and carry on
				else if(e.getMessage().equals("AUTH_SUCCESS") && isSecureConnection){

					isAuthenticated = true;
					System.out.println("Client authenticated the file server!");
				}
				// Handler to list files that this user is allowed to see
				else if(e.getMessage().equals("LFILES") && isSecureConnection && isAuthenticated)
				{
				    //Do error handling
				    response = new Envelope("FAIL");
				    if(e.getObjContents().size() < 1) {
				    	response = new Envelope("FAIL-BADCONTENTS");
				    }
				    else {
				    	if(e.getObjContents().get(0) == null) {
				    		response = new Envelope("FAIL-BADTOKEN");
				    	}
				    	else {

				    		//Prepare output list of file names and retrieve the token from the envelope
						    ArrayList<String> filteredFiles = new ArrayList<String>();
						    UserToken tok = (UserToken)e.getObjContents().get(0);
						    // Verify Token
						    if (verifiyToken(tok)) {

						   		//Get all files from the FileServer
							    ArrayList<ShareFile> all = FileServer.fileList.getFiles();

							    //Go through all files in the server, filter for only those in the right group
							    for(ShareFile f : all){

						    		if(tok.getGroups().contains(f.getGroup())) 
						    		{
						    			String path = f.getPath();
							    		path = path.substring(0, path.length() - f.getGroup().length());
						    			filteredFiles.add(path);
						    		}
						    	}


						    	//form response, write it
						    	response = new Envelope("OK");
							    response.addObject(filteredFiles);
							} else {
								System.out.println("TOKEN ERROR.");
							}
				    	}
				    }
				    output.writeObject(buildSuper(response));
					System.out.println("SENT from LFILES: " + response);   	
				}
				if(e.getMessage().equals("LFILESG") && isSecureConnection && isAuthenticated) //List only files in specified group
				{
				    //Do error handling
				    if(e.getObjContents().size() < 1) 
				    {
				    	response = new Envelope("FAIL-BADCONTENTS");
				    }
				    else 
				    {
				    	if(e.getObjContents().get(0) == null) 
				    	{
				    		response = new Envelope("FAIL-BADTOKEN");
				    	}
				    	else 
				    	{
				    		response = new Envelope("FAIL");
				    		//Prepare output list of file names and retrieve the token from the envelope
						    ArrayList<String> finalFiles = new ArrayList<String>();
						    ArrayList<ShareFile> filteredFiles = new ArrayList<ShareFile>();
						    String groupName = (String)e.getObjContents().get(0);
						    UserToken tok = (UserToken)e.getObjContents().get(1);
						    if (verifiyToken(tok)) {

							    //Get all files from the FileServer
							    ArrayList<ShareFile> all = FileServer.fileList.getFiles();

							    //Go through all files in the server, filter for only those in the right group
							    for(ShareFile f : all)
							    {
								    	if(tok.getGroups().contains(f.getGroup()))
							    		filteredFiles.add(f);
						    	}
						    	//Go through all filtered files, only return one group's
							    for(ShareFile f : filteredFiles)
							    {
							    	if(f.getGroup().equals(groupName))
							    	{
							    		String path = f.getPath();
							    		path = path.substring(0, path.length() - groupName.length());
							    		finalFiles.add(path);
						    		}
						    	}
						  
					    		//form response, write it
					    		response = new Envelope("OK");
					    		response.addObject(finalFiles);
					    	}
					    }
					}
					output.writeObject(buildSuper(response));
					System.out.println("SENT from LFILESG: " + response);
				}   	
				if(e.getMessage().equals("UPLOADF") && isSecureConnection && isAuthenticated)
				{

					if(e.getObjContents().size() < 3)
					{
						response = new Envelope("FAIL-BADCONTENTS");
					}
					else
					{
						if(e.getObjContents().get(0) == null) {
							response = new Envelope("FAIL-BADPATH");
						}
						if(e.getObjContents().get(1) == null) {
							response = new Envelope("FAIL-BADGROUP");
						}
						if(e.getObjContents().get(2) == null) {
							response = new Envelope("FAIL-BADTOKEN");
						}
						else {
							response = new Envelope("FAIL");
							String remotePath = (String)e.getObjContents().get(0);
							String group = (String)e.getObjContents().get(1);
							remotePath = remotePath + group;
							UserToken yourToken = (UserToken)e.getObjContents().get(2); //Extract token
							if (verifiyToken(yourToken)) {
								if (FileServer.fileList.checkFile(remotePath)) {
									System.out.printf("Error: file already exists at %s\n", remotePath);
									response = new Envelope("FAIL-FILEEXISTS"); //Success
									System.out.println("SENT from UPLOADF - FAIL-FILEEXISTS: " + response);
								}
								else if (!yourToken.getGroups().contains(group)) {
									System.out.printf("Error: user missing valid token for group %s\n", group);
									response = new Envelope("FAIL-UNAUTHORIZED"); //Success
									System.out.println("SENT from UPLOADF - FAIL-UNAUTHORIZED: " + response);
								}
								else  {
									File file;
									FileOutputStream fos;
									file = new File("shared_files/"+remotePath.replace('/', '_'));
									file.createNewFile();
									fos = new FileOutputStream(file);
									System.out.printf("Successfully created file %s\n", remotePath.replace('/', '_'));

									response = new Envelope("READY"); //Success
									output.writeObject(buildSuper(response));
									System.out.println("SENT from UPLOADF - READY: " + response);

									e = extractInner((Envelope)input.readObject());
									while (e.getMessage().compareTo("CHUNK")==0) {
										fos.write((byte[])e.getObjContents().get(0), 0, (Integer)e.getObjContents().get(1));
										response = new Envelope("READY"); //Success
										output.writeObject(buildSuper(response));
										System.out.println("SENT from UPLOADF - READYCHUNK: " + response);
										e = extractInner((Envelope)input.readObject());
									}

									if(e.getMessage().compareTo("EOF")==0) {
										System.out.printf("Transfer successful file %s\n", remotePath);
										FileServer.fileList.addFile(yourToken.getSubject(), group, remotePath);
										response = new Envelope("OK"); //Success
									}
									else {
										System.out.printf("Error reading file %s from client\n", remotePath);
										response = new Envelope("ERROR-TRANSFER"); //Success
									}
									fos.close();
								}
							}
						}
					}

					output.writeObject(buildSuper(response));
					System.out.println("SENT from UPLOADF: " + response);
				}
				else if (e.getMessage().equals("DOWNLOADF") && isSecureConnection && isAuthenticated) 
				{

					String remotePath = (String)e.getObjContents().get(0);
					Token t = (Token)e.getObjContents().get(1);
					if (verifiyToken(t)) {
						ShareFile sf = FileServer.fileList.getFile("/"+remotePath);

						if (sf == null) 
						{
							System.out.printf("Error: File %s doesn't exist\n", remotePath);
							e = new Envelope("ERROR_FILEMISSING");
							output.writeObject(buildSuper(e));
							System.out.println("SENT from DOWNLOADF - ERROR_FILEMISSING: " + e);

						}	
						else if (!t.getGroups().contains(sf.getGroup()))
						{
							System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
							e = new Envelope("ERROR_PERMISSION");
							output.writeObject(buildSuper(e));
							System.out.println("SENT from DOWNLOADF - ERROR_PERMISSION: " + e);
						}
						else {

							try
							{
								File f = new File("shared_files/_"+remotePath.replace('/', '_'));
								if (!f.exists()) 
								{
									System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
									e = new Envelope("ERROR_NOTONDISK");
									output.writeObject(buildSuper(e));
									System.out.println("SENT from DOWNLOADF - ERROR_NOTONDISK: " + e);
								}
								else 
								{
									FileInputStream fis = new FileInputStream(f);

									do {
										byte[] buf = new byte[4096];
										if (e.getMessage().compareTo("DOWNLOADF")!=0) 
										{
											System.out.printf("Server error: %s\n", e.getMessage());
											break;
										}
										e = new Envelope("CHUNK");
										int n = fis.read(buf); //can throw an IOException
										if (n > 0) 
										{
											System.out.printf(".");
										} 
										else if (n < 0) 
										{
											System.out.println("Read error");		
										}

										e.addObject(buf);
										e.addObject(new Integer(n));

										output.writeObject(buildSuper(e));
										System.out.println("SENT from DOWNLOADF: " + e);

										e = extractInner((Envelope)input.readObject());
									}
									while (fis.available()>0);

									//If server indicates success, return the member list
									if(e.getMessage().compareTo("DOWNLOADF")==0 && isSecureConnection  && isAuthenticated)
									{

										e = new Envelope("EOF");
										output.writeObject(buildSuper(e));
										System.out.println("SENT from DOWNLOADF - EOF: " + e);

										e = extractInner((Envelope)input.readObject());
										if(e.getMessage().compareTo("OK")==0) {
											System.out.printf("File data download successful\n");
										}
										else {
											System.out.printf("Upload failed: %s\n", e.getMessage());
										}
									}
									else {

										System.out.printf("Upload failed: %s\n", e.getMessage());
									}
								}
							}
							catch(Exception e1)
							{
								System.err.println("Error: " + e.getMessage());
								e1.printStackTrace(System.err);
							}
						}
					}
				}
				else if (e.getMessage().compareTo("DELETEF")==0 && isSecureConnection && isAuthenticated) {
					String remotePath = (String)e.getObjContents().get(0);
					Token t = (Token)e.getObjContents().get(1);
					if (verifiyToken(t)) {
						ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
						if (sf == null) {
							System.out.printf("Error: File %s doesn't exist\n", remotePath);
							e = new Envelope("ERROR_DOESNTEXIST");
						}
						else if (!t.getGroups().contains(sf.getGroup())){
							System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
							e = new Envelope("ERROR_PERMISSION");
						}
						else {

							try
							{
								File f = new File("shared_files/"+"_"+remotePath.replace('/', '_'));

								if (!f.exists()) {
									System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
									e = new Envelope("ERROR_FILEMISSING");
								}
								else if (f.delete()) {
									System.out.printf("File %s deleted from disk\n", "_"+remotePath.replace('/', '_'));
									FileServer.fileList.removeFile("/"+remotePath);
									e = new Envelope("OK");
								}
								else {
									System.out.printf("Error deleting file %s from disk\n", "_"+remotePath.replace('/', '_'));
									e = new Envelope("ERROR_DELETE");
								}
							}
							catch(Exception e1)
							{
								System.err.println("Error: " + e1.getMessage());
								e1.printStackTrace(System.err);
								e = new Envelope(e1.getMessage());
							}
						}
					}
					output.writeObject(buildSuper(e));
					System.out.println("SENT from DELETEF: " + e);

				}
				else if(e.getMessage().equals("DISCONNECT"))
				{
					socket.close();
					proceed = false;
				}
			} while(proceed);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}

	private boolean verifiyToken(UserToken token) {
		serverPublicKey = loadServerKey();
		SealedObject recvSignedHash = token.getSignedHash();
		byte[] recvHash = (byte[])CipherBox.decrypt(recvSignedHash, serverPublicKey);
		byte[] hashToken = Hasher.hash(token);
		if (!MessageDigest.isEqual(recvHash, hashToken)) {
			return false;
		}
		return true;
	}

	// Load the groupserver public key
	public PublicKey loadServerKey() {
		if (serverPublicKey == null) {
			try {
				File fsPublicKey = new File("groupserverpublic.key");
				FileInputStream keyIn = new FileInputStream("groupserverpublic.key");
				byte[] encPublicKey = new byte[(int) fsPublicKey.length()];
				keyIn.read(encPublicKey);
				keyIn.close();
				KeyFactory kf = KeyFactory.getInstance("RSA", "BC");
				X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encPublicKey);
				PublicKey publicKey = kf.generatePublic(publicKeySpec);
				System.out.println("Loaded in the server public key");
				return publicKey;
			} catch (Exception e) {
				System.out.println("You need the servers Public Key.");
				return null;
			}
		}
		return serverPublicKey;
	}
}
