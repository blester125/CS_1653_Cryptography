/* File worker thread handles the business of uploading, downloading, and removing files for clients with valid tokens */

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.X509EncodedKeySpec;
import java.security.SecureRandom;
import java.util.ArrayList;

import javax.crypto.KeyAgreement;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class FileThread extends Thread
{
	private final Socket socket;
	private boolean isSecureConnection;
	private boolean isAuthenticated;
	private SecretKey sessionKey;
	private KeyPair rsaPair;
	// Group Server Public Key
	public PublicKey serverPublicKey = null;
	private String groupServerPath = "groupserverpublic.key";
	private String fileServerPublicPath = "fileserverpublic.key";
	private String fileServerPrivatePath = "fileserverprivate.key";
	private int sequenceNumber;

	public FileThread (Socket _socket, KeyPair _rsaPair) {
		socket = _socket;
		rsaPair = _rsaPair;
		isSecureConnection = false;
		isAuthenticated = false;
		
	}

	//buildSuper and extractInner are now static functions within Envelope

	// public Envelope buildSuper (Envelope env) {
	// 	IvParameterSpec ivspec = CipherBox.generateRandomIV();			
	// 	Envelope superEnv = new Envelope("SUPER");
	// 	superEnv.addObject(CipherBox.encrypt(env, secretKey, ivspec));
	// 	superEnv.addObject(ivspec.getIV());
	// 	return superEnv;
	// }

	// public Envelope extractInner(Envelope superInputEnv){
	// 	SealedObject innerEnv = (SealedObject)superInputEnv.getObjContents().get(0);
	// 	IvParameterSpec decIVSpec = new IvParameterSpec((byte[])superInputEnv.getObjContents().get(1));
	// 	Envelope env = (Envelope)CipherBox.decrypt(innerEnv, secretKey, decIVSpec);
	// 	return env;
	// }

	public void run()
	{
		boolean proceed = true;
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

		try
		{
			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
			final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
			final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
			Envelope response = null;

			do
			{
				Envelope e = null;

				if(!isSecureConnection) {
					try {
						e = (Envelope)input.readObject();
					} catch(Exception exception) {
						exception.printStackTrace();
						sendFail(response, output);
						continue;
					}
				}
				else {
					try {
						e = Envelope.extractInner((Envelope)input.readObject(), sessionKey);
					} catch(Exception exception) {
						exception.printStackTrace();
						sendFail(response, output);
						continue;
					}
				}
				// null envelope check
				if(e == null) {
					sendFail(response, output);
					continue;
				}

				System.out.println("Request received: " + e.getMessage());

				// Client wishes to establish a shared symmetric secret key
				/*if(e.getMessage().equals("SESSIONKEY") && e.getObjContents() != null && e.getObjContents().get(0) != null) {

					// Retrieve Client's public key
					PublicKey clientPK = (PublicKey)e.getObjContents().get(0);
					KeyPair keypair = null;
					KeyAgreement keyAgreement = null;

					// generate secret key and send back public key
					try {

						keypair = DiffieHellman.genKeyPair();
						keyAgreement = DiffieHellman.genKeyAgreement(keypair);
						sessionKey = DiffieHellman.generateSecretKey(clientPK, keyAgreement);

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
				}*/
				if (e.getMessage().equals("REQUEST")) {
					rsaPair = RSA.loadRSA(fileServerPublicPath, fileServerPrivatePath);
					response = new Envelope("REQ-RESPONSE");
					response.addObject(rsaPair.getPublic());
					System.out.println("-----REQUEST - Sending my Public Key to User-----");
					System.out.println("Sent: ");
					System.out.println(response + "\n");
					output.writeObject(response);
				}
				// TODO add send Fails
				else if (e.getMessage().equals("SIGNED-DIFFIE-HELLMAN")) {
					response = new Envelope("Fail");
					System.out.println("-----SIGENED-DIFFIE-HELLMAN - User Sends Public Key-----");
					System.out.println("Received:");
					System.out.println(e + "\n");
					if (e.getObjContents().size() == 1) {
						if (e.getObjContents().get(0) != null) {
							// Recive Public Key from the user.
							SealedObject sealedKey;
							//= (SealedObject)e.getObjContents().get(0);
							//PublicKey userPublicKey = (PublicKey)CipherBox.decrypt(sealedKey, rsaPair.getPrivate());
							PublicKey userPublicKey = (PublicKey)e.getObjContents().get(0);
							try {
								// Send the Second Message
								Envelope message1 = new Envelope("SIGNED-DIFFIE-HELLMAN-2");
								System.out.println("-----SIGENED-DIFFIE-HELLMAN - Sending my Diffie Hellman Keys-----");
								KeyPair keyPair = DiffieHellman.genKeyPair();
								KeyAgreement keyAgreement = DiffieHellman.genKeyAgreement(keyPair); 
								// Hash my public key
								byte[] hashedPublicKey = Hasher.hash(keyPair.getPublic());
								// Encrypt my public key
								sealedKey = CipherBox.encrypt(hashedPublicKey, rsaPair.getPrivate());
								message1.addObject(sealedKey);
								message1.addObject(keyPair.getPublic());
								System.out.println("Sending:");
								System.out.println(message1 + "\n");
								// Send the message
								output.writeObject(message1);
								// Recv thrid message
								Envelope message2 = (Envelope)input.readObject();
								System.out.println("-----SIGNED-DIFFIE-HELLMAN - Receiving the users Diffie Hellman Keys-----");
								System.out.println("Received Message: ");
								System.out.println(message2 + "\n");
								if (message2 != null) {
									if (message2.getMessage().equals("SIGNED-DIFFIE-HELLMAN-3")) {
										if (message2.getObjContents().size() ==2) {
											if (message2.getObjContents().get(0) != null) {
												if (message2.getObjContents().get(1) != null) {
													SealedObject sealedHash = (SealedObject)message2.getObjContents().get(0);
													byte[] recvHash = (byte[])CipherBox.decrypt(sealedHash, userPublicKey);
													PublicKey recvKey = (PublicKey)message2.getObjContents().get(1);
													System.out.println("Verify that the signed hash matches the hash of the public key");
													if (Hasher.verifyHash(recvHash, recvKey)) {
														System.out.println("Hashes Matched.");
														System.out.print("Session Key created: ");
														sessionKey = DiffieHellman.generateSecretKey(recvKey, keyAgreement);
														System.out.println(sessionKey);
														System.out.println("-----SIGNED-DIFFIE-HELLMAN - Sending the Success Hash and Inital Sequence Number-----");
														Envelope message3 = new Envelope("SUCCESS");
														String keyPlusWord = CipherBox.getKeyAsString(sessionKey);
														keyPlusWord = keyPlusWord + "fileserver";
														byte[] hashResponse = Hasher.hash(keyPlusWord);
														message3.addObject(hashResponse);
														SecureRandom rand = new SecureRandom();
														int sequenceNumber = rand.nextInt(101);
														System.out.println("Inital Sequence Number: " + sequenceNumber);
														message3.addObject(sequenceNumber);
														System.out.println("Sending: ");
														System.out.println(message3 + "\n");
														Envelope superMessage3 = Envelope.buildSuper(message3, sessionKey);
														output.writeObject(superMessage3);
														// Recv 5th message
														Envelope superMessage4 = (Envelope)input.readObject();
														System.out.println("-----SIGNED-DIFFIE-HELLMAN - Checking the Client Succes Hash-----");
														Envelope message4 = Envelope.extractInner(superMessage4, sessionKey);
														System.out.println("Received:");
														System.out.println(message4 + "\n");
														if (message4 != null) {
															if (message4.getMessage().equals("SUCCESS")) {
																if (message4.getObjContents().size() == 2) {
																	if (message4.getObjContents().get(0) != null) {
																		if (message4.getObjContents().get(1) != null) {
																			byte[] recvHashWord = (byte[])message4.getObjContents().get(0);
																			keyPlusWord = CipherBox.getKeyAsString(sessionKey);
																			keyPlusWord = keyPlusWord + "client";
																			System.out.println("Verify the received hash matches the hash of the sessionKey plus \"client\"");
																			if (Hasher.verifyHash(recvHashWord, keyPlusWord)) {
																				System.out.println("Hashed Matched");
																				Integer seq = (Integer)message4.getObjContents().get(1);
																				int seqNum = seq.intValue();
																				System.out.println("Checking sequence number");
																				if (seqNum == sequenceNumber + 1) {
																					System.out.println("Sequence number is Correct");
																					sequenceNumber += 2;
																					System.out.println("New sequence number: " + sequenceNumber);
																					isSecureConnection = true;
																					isAuthenticated = true;
																					System.out.println("\nSecure and Authenticated connection established with the File Client");
																				}
																			}
																		}
																	}
																}
															}
														}
													}
												}
											}
										}
									}
								}
							} catch (Exception error) {
								response = new Envelope("FAIL");
								sendFail(response, output);
							}
						}
					} 
				}
				// Client sends server the challenge, server will decrypt and respond
				else if(e.getMessage().equals("CHALLENGE") && isSecureConnection){
					try {
						// null checks
						if(e.getObjContents() == null || e.getObjContents().size() < 1) {
					    	response = new Envelope("FAIL-BADCONTENTS");
						}
						else if(e.getObjContents().get(0) == null) {
							response = new Envelope("FAIL");
						}
						//Recover sealedobject of challenge from envelope, then decrypt
						SealedObject encRSA_R1 = (SealedObject)e.getObjContents().get(0);
						BigInteger r1 = (BigInteger)CipherBox.decrypt(encRSA_R1, rsaPair.getPrivate());

						//build envelope
						response = new Envelope("CH_RESPONSE");
						response.addObject(r1);

						//send it back
						output.writeObject(Envelope.buildSuper(response, sessionKey));
						System.out.println("SENT from CHALLENGE: " + response);
					} catch (Exception exception) {
						exception.printStackTrace();
						response = new Envelope("FAIL");
						response.addObject(response);
						output.writeObject(Envelope.buildSuper(response, sessionKey));
					}

				}
				// If successful, set your flag and carry on
				else if(e.getMessage().equals("AUTH_SUCCESS") && isSecureConnection) {
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
						    if (verifyToken(tok)) {

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
				    output.writeObject(Envelope.buildSuper(response, sessionKey));
					System.out.println("SENT from LFILES: " + response);   	
				}
				if(e.getMessage().equals("LFILESG") && isSecureConnection && isAuthenticated) //List only files in specified group
				{
				    //Do error handling
				    if(e.getObjContents()== null || e.getObjContents().size() < 1) 
				    {
				    	response = new Envelope("FAIL-BADCONTENTS");
				    }
				    else 
				    {
				    	if(e.getObjContents().get(0) == null) {
							response = new Envelope("FAIL-BADGROUP");
				    	}
				    	else if(e.getObjContents().get(1) == null) 
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
						    if (verifyToken(tok)) {

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
					output.writeObject(Envelope.buildSuper(response, sessionKey));
					System.out.println("SENT from LFILESG: " + response);
				}   	
				if(e.getMessage().equals("UPLOADF") && isSecureConnection && isAuthenticated)
				{

					if(e.getObjContents() == null || e.getObjContents().size() < 4)
					{
						response = new Envelope("FAIL-BADCONTENTS");
					}
					else
					{
						if(e.getObjContents().get(0) == null) {
							response = new Envelope("FAIL-BADPATH");
						}
						else if(e.getObjContents().get(1) == null) {
							response = new Envelope("FAIL-BADGROUP");
						}
						else if(e.getObjContents().get(2) == null) {
							response = new Envelope("FAIL-BADTOKEN");
						}
						else if(e.getObjContents().get(3) == null){
							response = new Envelope("FAIL-BADMETADATA");
						}
						else {
							response = new Envelope("FAIL");
							String remotePath = (String)e.getObjContents().get(0);
							String group = (String)e.getObjContents().get(1);
							remotePath = remotePath + group;
							UserToken yourToken = (UserToken)e.getObjContents().get(2); //Extract token
							if (verifyToken(yourToken)) {
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
									output.writeObject(Envelope.buildSuper(response, sessionKey));
									System.out.println("SENT from UPLOADF - READY: " + response);

									e = Envelope.extractInner((Envelope)input.readObject(), sessionKey);
									while (e.getMessage().compareTo("CHUNK")==0) {
										fos.write(((byte[])e.getObjContents().get(0)), 0, (Integer)e.getObjContents().get(1));
										response = new Envelope("READY"); //Success
										output.writeObject(Envelope.buildSuper(response, sessionKey));
										System.out.println("SENT from UPLOADF - READYCHUNK: " + response);
										e = Envelope.extractInner((Envelope)input.readObject(), sessionKey);
									}

									if(e.getMessage().compareTo("EOF")==0) {
										if(e.getObjContents() != null && e.getObjContents().size() == 3)
										{
											if(e.getObjContents().get(0) == null){
												System.err.println("Error: null key index field");
											}
											else if(e.getObjContents().get(1) == null){
												System.err.println("Error: null key version field");
											}
											else if(e.getObjContents().get(2) == null){
												System.err.println("Error: null IV field");
											}
											else {
												int keyIndex = ((Integer)e.getObjContents().get(0)).intValue();
												int keyVersion = ((Integer)e.getObjContents().get(1)).intValue();
												IvParameterSpec iv = (IvParameterSpec)e.getObjContents().get(2);
												System.out.printf("Transfer successful file %s\n", remotePath);
												FileServer.fileList.addFile(yourToken.getSubject(), group, 
														remotePath, keyIndex, keyVersion, iv);
												response = new Envelope("OK"); //Success
											}
										}
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

					output.writeObject(Envelope.buildSuper(response, sessionKey));
					System.out.println("SENT from UPLOADF: " + response);
				}
				else if (e.getMessage().equals("DOWNLOADF") && isSecureConnection && isAuthenticated) 
				{

					String remotePath = (String)e.getObjContents().get(0);
					Token t = (Token)e.getObjContents().get(1);
					if(e.getObjContents() == null || e.getObjContents().size() < 2) {
						response = new Envelope("FAIL-BADCONTENTS");
					}
					else if(e.getObjContents().get(0) == null) {
						response = new Envelope("FAIL-BADPATH");
					}
					else if(e.getObjContents().get(1) == null) {
						response = new Envelope("FAIL-BADTOKEN");
					}
					else if (verifyToken(t)) {
						ShareFile sf = FileServer.fileList.getFile("/"+remotePath);

						if (sf == null) 
						{
							System.out.printf("Error: File %s doesn't exist\n", remotePath);
							response = new Envelope("ERROR_FILEMISSING");
							System.out.println("SENT from DOWNLOADF - ERROR_FILEMISSING: " + e);

						}	
						else if (!t.getGroups().contains(sf.getGroup()))
						{
							System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
							response = new Envelope("ERROR_PERMISSION");
							System.out.println("SENT from DOWNLOADF - ERROR_PERMISSION: " + response);
						}
						else {

							try
							{
								File f = new File("shared_files/_"+remotePath.replace('/', '_'));
								if (!f.exists()) 
								{
									System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
									response = new Envelope("ERROR_NOTONDISK");
									System.out.println("SENT from DOWNLOADF - ERROR_NOTONDISK: " + response);
								}
								else 
								{
									FileInputStream fis = new FileInputStream(f);
									boolean sentMetadata = false;
									do {
										byte[] buf = new byte[4096];
										if (e.getMessage().compareTo("DOWNLOADF")!=0) 
										{
											System.out.printf("Server error: %s\n", e.getMessage());
											break;
										}
										response = new Envelope("CHUNK");
										int n = fis.read(buf); //can throw an IOException
										if (n > 0) 
										{
											System.out.printf(".");
										} 
										else if (n < 0) 
										{
											System.out.println("Read error");
											sendFail(response, output);
										}

										response.addObject(buf);
										response.addObject(new Integer(n));
										// send meta-data along with the first chunk of the file
										if(!sentMetadata) {
											response.addObject(new Integer(sf.getKeyIndex()));
											response.addObject(new Integer(sf.getKeyVersion()));
											response.addObject(sf.getIvParameterSpec());
											sentMetadata = true;
										}

										output.writeObject(Envelope.buildSuper(response, sessionKey));
										System.out.println("SENT from DOWNLOADF: " + response);

										e = Envelope.extractInner((Envelope)input.readObject(), sessionKey);
									}
									while (fis.available()>0);

									//If server indicates success, return the member list
									if(e != null && e.getMessage().compareTo("DOWNLOADF")==0 && isSecureConnection  && isAuthenticated)
									{

										response = new Envelope("EOF");
										output.writeObject(Envelope.buildSuper(response, sessionKey));
										System.out.println("SENT from DOWNLOADF - EOF: " + response);

										e = Envelope.extractInner((Envelope)input.readObject(), sessionKey);
										if(e.getMessage().compareTo("OK")==0) {
											System.out.printf("File data download successful\n");
										}
										else {
											System.out.printf("Upload failed: %s\n", e.getMessage());
											sendFail(response, output);
										}
									}
									else {

										System.out.printf("Upload failed: %s\n", e.getMessage());
										sendFail(response, output);
									}

									fis.close();
								}
							}
							catch(Exception e1)
							{
								System.err.println("Error: " + e.getMessage());
								e1.printStackTrace(System.err);
								sendFail(response, output);
							}
						}
					}
					
					output.writeObject(Envelope.buildSuper(response, sessionKey));
					System.out.println("SENT from UPLOADF: " + response);
				}
				else if (e.getMessage().compareTo("DELETEF")==0 && isSecureConnection && isAuthenticated) {
					if(e.getObjContents() == null || e.getObjContents().size() < 2) {
						response = new Envelope("FAIL-BADCONTENTS");
						output.writeObject(response);
						continue;
					}
					String remotePath = (String)e.getObjContents().get(0);
					Token t = (Token)e.getObjContents().get(1);
					if(e.getObjContents().get(0) == null){
						response = new Envelope("FAIL-BADPATH");
					}
					else if(e.getObjContents().get(1) == null){
						response = new Envelope("FAIL-BADTOKEN");
					}
					else if (verifyToken(t)) {
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
					output.writeObject(Envelope.buildSuper(e, sessionKey));
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

	private boolean verifyToken(UserToken token) {
		// check for token freshness
		System.out.println("verify");
		if(!token.isFresh()) {
			System.out.println("old token");
			return false;
		}

		//check token to ensure expected and actual public keys match
		if (KeyBox.compareKey(token.getPublicKey(), rsaPair.getPublic())) {
			return false;
		}

		//get group server public key
		serverPublicKey = RSA.loadServerKey(groupServerPath);
		SealedObject recvSignedHash = token.getSignedHash();
		byte[] recvHash = (byte[])CipherBox.decrypt(recvSignedHash, serverPublicKey);
		byte[] hashToken = Hasher.hash(token);
		if (!MessageDigest.isEqual(recvHash, hashToken)) {
			return false;
		}
		return true;
	}
	
	/**
	 * creates a FAIL response
	 * @param response	envelope being send
	 * @param ouput	output stream being sent through
	 */
	private void sendFail(Envelope response, ObjectOutputStream output) {
		response = new Envelope("FAIL");
		response.addObject(response);
		try {
			output.writeObject(Envelope.buildSuper(response, sessionKey));
		} catch (IOException e) {
			e.printStackTrace();
		} catch (NullPointerException e1) {
			try {
				output.writeObject(response);
			} catch (Exception e2) {
				e2.printStackTrace();
			}
		}
	}
}
