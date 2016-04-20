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
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.Date;

import javax.crypto.KeyAgreement;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;

/* File worker thread handles the business of 
   uploading, downloading, and removing files 
   for clients with valid tokens */
public class FileThread extends Thread
{
	private final Socket socket;
	private boolean isSecureConnection;
	private boolean isAuthenticated;
	private boolean solvePuzzle;
	private SecretKey sessionKey;
	private KeyPair rsaPair;
	// Group Server Public Key
	public PublicKey serverPublicKey = null;
	private String groupServerPath = "groupserverpublic.key";
	private int sequenceNumber;
	private final int puzzleSize = 5;

	public FileThread (Socket _socket, KeyPair _rsaPair) {
		socket = _socket;
		rsaPair = _rsaPair;
		isSecureConnection = false;
		isAuthenticated = false;
		solvePuzzle = false;
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
				if (e.getMessage().equals("PUZZLE")) {
					System.out.println("Sending Puzzle");
					// Make puzzle
					byte[] answer = Hasher.generatePuzzle(puzzleSize);
					Date now = new Date();
					Envelope puzzle = new Envelope("PUZZLEOK");
					puzzle.addObject(Hasher.hash(answer));
					puzzle.addObject(new Integer(puzzleSize));
					// encrypt answer
					Envelope answerEnv = new Envelope("ANSWER");
					answerEnv.addObject(answer);
					answerEnv.addObject(now);
					//SealedObject sealedAnswer = (SealedObject)CipherBox.encrypt(answerEnv, rsaPair.getPublic());
					SecretKey puzzleKey = KeyBox.convertPrivateKey(rsaPair.getPrivate());
					Envelope sealedAnswer = Envelope.buildSuper(answerEnv, puzzleKey);
					puzzle.addObject(sealedAnswer);
					System.out.println(puzzle);
					output.writeObject(puzzle);
					proceed = false;
				}
				else if (e.getMessage().equals("REQUEST")) {
					response = new Envelope("REQ-RESPONSE");
					response.addObject(rsaPair.getPublic());
					System.out.println("-----REQUEST - Sending my Public Key to User-----");
					System.out.println("Sent: ");
					System.out.println(response + "\n");
					output.writeObject(response);
				}
				else if (e.getMessage().equals("SIGNED-DIFFIE-HELLMAN")) {
					response = new Envelope("Fail");
					System.out.println("-----SIGENED-DIFFIE-HELLMAN - User Sends Public Key-----");
					System.out.println("Received:");
					System.out.println(e + "\n");
					if (e.getObjContents().size() == 3) {
						if (e.getObjContents().get(0) != null) {
							if (e.getObjContents().get(1) != null) {
								if (e.getObjContents().get(2) != null) {
									// Recive Public Key from the user.
									// get the answer and check
									PublicKey userPublicKey = (PublicKey)e.getObjContents().get(0);
									byte[] answer = (byte[])e.getObjContents().get(1);
									//SealedObject sealedAnswer = (SealedObject)e.getObjContents().get(2);
									Envelope sealedAnswer = (Envelope)e.getObjContents().get(2);
									SecretKey puzzleKey = KeyBox.convertPrivateKey(rsaPair.getPrivate());
									//Envelope realAnswer = (Envelope)CipherBox.decrypt(sealedAnswer, rsaPair.getPrivate());
									Envelope realAnswer = Envelope.extractInner(sealedAnswer, puzzleKey);
									if (realAnswer != null) {
										if (realAnswer.getObjContents().size() == 2) {
											if (realAnswer.getObjContents().get(0) != null) {
												if (realAnswer.getObjContents().get(1) != null) {
													byte[] myAnswer = (byte[])realAnswer.getObjContents().get(0);
													Date timestamp = (Date)realAnswer.getObjContents().get(1);
													if (isFresh(timestamp)) {
														if (MessageDigest.isEqual(myAnswer, answer)) {
															solvePuzzle = true;
															try {
																// Send the Second Message
																Envelope message1 = new Envelope("SIGNED-DIFFIE-HELLMAN-2");
																System.out.println("-----SIGENED-DIFFIE-HELLMAN - Sending my Diffie Hellman Keys-----");
																KeyPair keyPair = DiffieHellman.genKeyPair();
																KeyAgreement keyAgreement = DiffieHellman.genKeyAgreement(keyPair); 
																// Hash my public key
																byte[] hashedPublicKey = Hasher.hash(keyPair.getPublic());
																// Encrypt my public key
																SealedObject sealedKey = CipherBox.encrypt(hashedPublicKey, rsaPair.getPrivate());
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
																						String keyPlusWord = KeyBox.getKeyAsString(sessionKey);
																						keyPlusWord = keyPlusWord + "fileserver";
																						byte[] hashResponse = Hasher.hash(keyPlusWord);
																						message3.addObject(hashResponse);
																						SecureRandom rand = new SecureRandom();
																						sequenceNumber = rand.nextInt(101);
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
																											keyPlusWord = KeyBox.getKeyAsString(sessionKey);
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
											}
										}	
									}
								}
							}
						}
					} 
				}
				// Handler to list files that this user is allowed to see
				else if(e.getMessage().equals("LFILES") 
							&& isSecureConnection 
							&& isAuthenticated
							&& solvePuzzle)
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
				    		if(e.getObjContents().get(1) == null) {
				    			response = new Envelope("FAIL-BADSEQNUM");
				    		}
				    		else {
				    			int tempseq = (Integer)e.getObjContents().get(1);
				    			if(tempseq == sequenceNumber + 1){
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
								    	sequenceNumber += 2;
								    	response = new Envelope("OK");
									    response.addObject(filteredFiles);
									    response.addObject(sequenceNumber);
									} else {
										System.out.println("TOKEN ERROR.");
									}
								} else {
									System.out.println("SEQNUM ERROR.");
								}
							}
				    	}
				    }
				    output.writeObject(Envelope.buildSuper(response, sessionKey));
					System.out.println("SENT from LFILES: " + response);   	
				}
				else if(e.getMessage().equals("LFILESG") 
						&& isSecureConnection 
						&& isAuthenticated
						&& solvePuzzle) //List only files in specified group
				{
				System.out.println(e);
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
				    	else if(e.getObjContents().get(2) == null) 
				    	{
				    		response = new Envelope("FAIL-BADSEQNUM");
				    	}
				    	else 
				    	{
						System.out.println("Expecting seqNum: " + (sequenceNumber + 1));	
				    		int tempseq = (Integer)e.getObjContents().get(2);
						System.out.println("Got: " + tempseq);
				    		if(tempseq == sequenceNumber + 1){
							System.out.println("Sequence number is OK");
					    		response = new Envelope("FAIL");
					    		//Prepare output list of file names and retrieve the token from the envelope
							    ArrayList<String> finalFiles = new ArrayList<String>();
							    ArrayList<ShareFile> filteredFiles = new ArrayList<ShareFile>();
							    String groupName = (String)e.getObjContents().get(0);
							    if (!groupName.equals("")) {
								    System.out.println("Group Name is not \"\"");
								    UserToken tok = (UserToken)e.getObjContents().get(1);
								    if (verifyToken(tok)) {
									System.out.println("TOKEN is verified");

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
							    		sequenceNumber += 2;
									System.out.println("New SeqNum: " + sequenceNumber);
							    		response = new Envelope("OK");
							    		response.addObject(finalFiles);
							    		response.addObject(sequenceNumber);
							    	}
							    }
							}
					    }
					}
					output.writeObject(Envelope.buildSuper(response, sessionKey));
					System.out.println("SENT from LFILESG: " + response);
				}   	
				else if(e.getMessage().equals("UPLOADF") 
							&& isSecureConnection 
							&& isAuthenticated
							&& solvePuzzle)
				{
					System.out.println("First RECEIVED: " + e);
					if(e.getObjContents() == null || e.getObjContents().size() < 3)
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
						else if(e.getObjContents().get(3) == null) {
							response = new Envelope("FAIL-BADSEQNUM");
						}
						else {
							int tempseq = (Integer)e.getObjContents().get(3);
				    		if(tempseq == sequenceNumber + 1){
								response = new Envelope("FAIL");
								String remotePath = (String)e.getObjContents().get(0);
								String group = (String)e.getObjContents().get(1);
								if (!group.equals("") && !remotePath.equals("")) {
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

											sequenceNumber += 2;
											response = new Envelope("READY"); //Success
											response.addObject(sequenceNumber);
											output.writeObject(Envelope.buildSuper(response, sessionKey));
											System.out.println("SENT from UPLOADF - READY: " + response);

											e = Envelope.extractInner((Envelope)input.readObject(), sessionKey);
											System.out.println("RECEIVED: " + e);
											while (e.getMessage().compareTo("CHUNK")==0) {
												if(e.getObjContents().get(0) != null){
													if(e.getObjContents().get(1) != null){
														if(e.getObjContents().get(2) != null){
															int seqchunk = (Integer)e.getObjContents().get(2);
															if(seqchunk == sequenceNumber + 1){
																fos.write(((byte[])e.getObjContents().get(0)));
																sequenceNumber += 2;
																response = new Envelope("READY"); //Success
																response.addObject(sequenceNumber);
																output.writeObject(Envelope.buildSuper(response, sessionKey));
																System.out.println("SENT from UPLOADF - READYCHUNK: " + response);
																e = Envelope.extractInner((Envelope)input.readObject(), sessionKey);
																System.out.println("RECEIVED: " + e);
															}
														}
													}
												}
											}
											System.out.println("I GOT: " + e);
											if(e.getMessage().compareTo("EOF")==0) {
												if(e.getObjContents() != null && e.getObjContents().size() == 6)
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
													else if(e.getObjContents().get(3) == null){
														System.err.println("Error: null block field");
													}
													else if(e.getObjContents().get(4) == null){
														System.err.println("Error: null file length field");
													}
													else if(e.getObjContents().get(5) == null){
														System.err.println("Error: null seq num field");
													}
													else {
													int eofseq = (Integer)e.getObjContents().get(5);
													System.out.println("Expected: " + (sequenceNumber+1));
													System.out.println("Got: " + eofseq);
				    									if(eofseq == sequenceNumber + 1){

															int keyIndex = ((Integer)e.getObjContents().get(0)).intValue();
															int keyVersion = ((Integer)e.getObjContents().get(1)).intValue();
															byte[] iv = (byte[])e.getObjContents().get(2);
															byte[] padBlock = (byte[])e.getObjContents().get(3);
															long fileLength = (Long)e.getObjContents().get(4);
															System.out.printf("Transfer successful file %s\n", remotePath);
															FileServer.fileList.addFile(yourToken.getSubject(), group, 
																	remotePath, keyIndex, keyVersion, iv, fileLength);
															sequenceNumber += 2;
															response = new Envelope("OK"); //Success
															response.addObject(sequenceNumber);
														}
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
						}
					}

					output.writeObject(Envelope.buildSuper(response, sessionKey));
					System.out.println("SENT from UPLOADF: " + response);
				}
				else if (e.getMessage().equals("DOWNLOADF") 
							&& isSecureConnection 
							&& isAuthenticated
							&& solvePuzzle) 
				{
					System.out.println("FIRST RECEIVED: " + e);
					int dSuccessFlag = 0;
					String remotePath = (String)e.getObjContents().get(0);
					if (!remotePath.equals("")) {
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
						else if(e.getObjContents().get(2) == null) {
							response = new Envelope("FAIL-BADSEQNUM");
						} 
						else if (verifyToken(t)) {

							int tempseq = (Integer)e.getObjContents().get(2);
							if(tempseq == sequenceNumber + 1){
								System.out.println("SequenceNumber OK");
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

												sequenceNumber += 2;
												response.addObject(buf);
												response.addObject(new Integer(n));
												// send meta-data along with the first chunk of the file
												if(!sentMetadata) {
													response.addObject(new Integer(sf.getKeyIndex()));
													response.addObject(new Integer(sf.getKeyVersion()));
													response.addObject(sf.getIv());
													response.addObject(sf.getLength());
													sentMetadata = true;
												}
												response.addObject(sequenceNumber);
												output.writeObject(Envelope.buildSuper(response, sessionKey));
												System.out.println("SENT from DOWNLOADF: " + response);

												e = Envelope.extractInner((Envelope)input.readObject(), sessionKey);
												System.out.println("RECEIVED: " + e);
												if(e.getObjContents().get(0) != null){
													int chunkSeq = (Integer)e.getObjContents().get(0);
													if(chunkSeq != sequenceNumber + 1){
														System.out.println("Error: seq num mismatch");
														break;
													}
												} else {
													break;
												}			
											}
											while (fis.available()>0);

											//If server indicates success, return the member list
											if(e != null && e.getMessage().compareTo("DOWNLOADF")==0 && isSecureConnection  && isAuthenticated)
											{
												sequenceNumber += 2;
												response = new Envelope("EOF");
												response.addObject(sequenceNumber);
												output.writeObject(Envelope.buildSuper(response, sessionKey));
												System.out.println("SENT from DOWNLOADF - EOF: " + response);

												e = Envelope.extractInner((Envelope)input.readObject(), sessionKey);
												System.out.println("GOT: " + e);
												if(e.getMessage().compareTo("OK")==0) {
													if(e.getObjContents().get(0) != null){
														int eofseq = (Integer)e.getObjContents().get(0);
														if(eofseq == sequenceNumber + 1){
															System.out.printf("File data download successful\n");
															dSuccessFlag = 1;
															sequenceNumber += 2;
														}
													}
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
						}
					}
					
					if(dSuccessFlag == 0){
						output.writeObject(Envelope.buildSuper(response, sessionKey));
					}
					//System.out.println("SENT from DOWNLOADF (NO WRITEOUT): " + response);
				}
				else if (e.getMessage().compareTo("DELETEF")==0 
							&& isSecureConnection 
							&& isAuthenticated
							&& solvePuzzle) {
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
					else if(e.getObjContents().get(2) == null){
						response = new Envelope("FAIL-BADSEQNUM");
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

							int tempseq = (Integer)e.getObjContents().get(2);
							if(tempseq == sequenceNumber + 1){

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
										sequenceNumber += 2;
										e = new Envelope("OK");
										e.addObject(sequenceNumber);
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
					}
					output.writeObject(Envelope.buildSuper(e, sessionKey));
					System.out.println("SENT from DELETEF: " + e);

				}
				else if(e.getMessage().equals("DISCONNECT"))
				{
					socket.close();
					proceed = false;
					isSecureConnection = false;
					isAuthenticated = false;
					solvePuzzle = false;
				}
			} while(proceed);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			isSecureConnection = false;
			isAuthenticated = false;
			solvePuzzle = false;
			proceed = false;
		}
	}

	private boolean verifyToken(UserToken token) {
		// check for token freshness
		if(!token.isFresh()) {
			System.out.println("old token");
			return false;
		}

		//check token to ensure expected and actual public keys match
		if (!KeyBox.compareKey(token.getPublicKey(), rsaPair.getPublic())) {
			return false;
		}

		//get group server public key
		serverPublicKey = RSA.loadServerKey(groupServerPath);
		SealedObject recvSignedHash = token.getSignedHash();
		byte[] recvHash = (byte[])CipherBox.decrypt(recvSignedHash, serverPublicKey);
		if (!Hasher.verifyHash(recvHash, token)) {
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

	public boolean isFresh(Date timestamp) {
		Date now = new Date();
		if ((now.getTime() - timestamp.getTime()) < 30000L) {
			return true;
		} 
		return false;
	}

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

	// Client sends server the challenge, server will decrypt and respond
				/*else if(e.getMessage().equals("CHALLENGE") && isSecureConnection){
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
				}*/
}
