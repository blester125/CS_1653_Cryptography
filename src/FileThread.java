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
					System.out.println(response);
					output.writeObject(response);
				}
				else if (e.getMessage().equals("SIGNED-DIFFIE-HELLMAN")) {
					response = new Envelope("Fail");
					System.out.println("RECV MESSAGE 1 USER PUBLIC KEY");
					if (e.getObjContents().size() == 1) {
						if (e.getObjContents().get(0) != null) {
							SealedObject sealedKey;
							//= (SealedObject)e.getObjContents().get(0);
							//PublicKey userPublicKey = (PublicKey)CipherBox.decrypt(sealedKey, rsaPair.getPrivate());
							PublicKey userPublicKey = (PublicKey)e.getObjContents().get(0);
							// Send second Message
							try {
								response = new Envelope("SIGNED-DIFFIE-HELLMAN-2");
								System.out.println(rsaPair.getPublic());
								KeyPair keyPair = DiffieHellman.genKeyPair();
								KeyAgreement keyAgreement = DiffieHellman.genKeyAgreement(keyPair); 
								byte[] hashedPublicKey = Hasher.hash(keyPair.getPublic());
								sealedKey = CipherBox.encrypt(hashedPublicKey, rsaPair.getPrivate());
								response.addObject(sealedKey);
								response.addObject(keyPair.getPublic());
								System.out.println("SENDING DH MESSAGE");
								System.out.println(response);
								System.out.println("SENDING DH2");
								output.writeObject(response);
								System.out.println("SENT DH2");
								// Recv thrid message
								Envelope check = (Envelope)input.readObject();
								System.out.println("RECVD 3rd message");
								System.out.println(check);
								if (check != null) {
									if (check.getMessage().equals("SIGNED-DIFFIE-HELLMAN-3")) {
										if (check.getObjContents().size() ==2) {
											if (check.getObjContents().get(0) != null) {
												if (check.getObjContents().get(1) != null) {
													SealedObject sealedHash = (SealedObject)check.getObjContents().get(0);
													byte[] recvHash = (byte[])CipherBox.decrypt(sealedHash, userPublicKey);
													PublicKey recvKey = (PublicKey)check.getObjContents().get(1);
													if (Hasher.verifyHash(recvHash, recvKey)) {
														System.out.println("MATCHING HASHES");
														sessionKey = DiffieHellman.generateSecretKey(recvKey, keyAgreement);
														Envelope resp = new Envelope("SUCCESS");
														String keyPlusWord = CipherBox.getKeyAsString(sessionKey);
														keyPlusWord = keyPlusWord + "fileserver";
														byte[] hashResponse = Hasher.hash(keyPlusWord);
														resp.addObject(hashResponse);
														SecureRandom rand = new SecureRandom();
														int sequenceNumber = rand.nextInt(101);
														resp.addObject(sequenceNumber);
														System.out.println("SENDING 4th message");
														System.out.println(resp);
														Envelope message = Envelope.buildSuper(resp, sessionKey);
														output.writeObject(message);
														// Recv 5th message
														check = (Envelope)input.readObject();
														System.out.println("RECVD 5th message");
														Envelope innerCheck = Envelope.extractInner(check, sessionKey);
														if (innerCheck != null) {
															if (innerCheck.getMessage().equals("SUCCESS")) {
																if (innerCheck.getObjContents().size() == 2) {
																	if (innerCheck.getObjContents().get(0) != null) {
																		if (innerCheck.getObjContents().get(1) != null) {
																			byte[] recvHashWord = (byte[])innerCheck.getObjContents().get(0);
																			keyPlusWord = CipherBox.getKeyAsString(sessionKey);
																			keyPlusWord = keyPlusWord + "client";
																			if (Hasher.verifyHash(recvHashWord, keyPlusWord)) {
																				Integer seq = (Integer)innerCheck.getObjContents().get(1);
																				int seqNum = seq.intValue();
																				if (seqNum == sequenceNumber + 1) {
																					sequenceNumber += 2;
																					isSecureConnection = true;
																					isAuthenticated = true;
																					System.out.println("SECURE AND AUTH'D CONNECTION");
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
