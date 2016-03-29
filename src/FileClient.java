/* FileClient provides all the client functionality regarding the file server */

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class FileClient extends Client implements FileClientInterface {
	private SecretKey sessionKey;
	public PublicKey cachedPublicKey;
	private String fileserverRegistry = "FileServerRegistry.bin";
	public PublicKey serverPublicKey = null;
	public String cachedKeyFingerprint;
	public String serverKeyFingerprint;
	public int sequenceNumber;
	
	public FileClient() {

	}

	//buildSuper and extractInner are now static functions within Envelope

	// public Envelope buildSuper(Envelope env){
	// 	IvParameterSpec ivspec = CipherBox.generateRandomIV();			
	// 	Envelope superEnv = new Envelope("SUPER");
	// 	superEnv.addObject(CipherBox.encrypt(env, secretKey, ivspec));
	// 	superEnv.addObject(ivspec.getIV());

	// 	return superEnv;
	// }
	
	// public PublicKey getCachedPublicKey() {
	// 	return this.cachedPublicKey;
	// }

	// public Envelope extractInner(Envelope superInputEnv){

	// 	SealedObject innerEnv = (SealedObject)superInputEnv.getObjContents().get(0);
	// 	IvParameterSpec decIVSpec = new IvParameterSpec((byte[])superInputEnv.getObjContents().get(1));
	// 	Envelope env = (Envelope)CipherBox.decrypt(innerEnv, secretKey, decIVSpec);

	// 	return env;
	// }

	public void disconnect()	 {
		if (isConnected()) {
			try {
				Envelope message = new Envelope("DISCONNECT");
				Envelope superE = Envelope.buildSuper(message, sessionKey);
				output.writeObject(superE);
				sock.close(); //close the socket
			}
			catch(Exception e) {
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
			}
		}
	}

	public boolean delete(String filename, String group, UserToken token) {

		String remotePath;

		if (filename.charAt(0)=='/') {
			remotePath = filename.substring(1);
		}
		else {
			remotePath = filename;
		}

		remotePath = remotePath + group;

		Envelope env = new Envelope("DELETEF"); //Success
		env.addObject(remotePath);
		env.addObject(token);

		try {

			//build nested envelope, encrypt, and send
			Envelope superEnv = Envelope.buildSuper(env, sessionKey);
			output.writeObject(superEnv);

			//receive, extract, and decrypt inner envelope
			env = Envelope.extractInner((Envelope)input.readObject(), sessionKey);
		   
			if (env.getMessage().compareTo("OK")==0) {

				System.out.printf("File %s deleted successfully\n", filename);				
			}
			else {

				System.out.printf("Error deleting file %s (%s)\n", filename, env.getMessage());
				return false;
			}			
		} catch (IOException e1) {

			e1.printStackTrace();
		} catch (ClassNotFoundException e1) {

			e1.printStackTrace();
		}  	
		return true;
	}

	public boolean download(String sourceFile, String destFile, String group, UserToken token, 
			GroupMetadata groupMetadata) {
		if (sourceFile.charAt(0)=='/') {
			sourceFile = sourceFile.substring(1);
		}
		sourceFile = sourceFile + group;			
		File file = new File(destFile);
    	try {		
			if (!file.exists()) {
			file.createNewFile();
			FileOutputStream fos = new FileOutputStream(file);
				    
			Envelope env = new Envelope("DOWNLOADF"); //Success
			env.addObject(sourceFile);
			env.addObject(token);

			//build nested envelope, encrypt, and send
			Envelope superEnv = Envelope.buildSuper(env, sessionKey);
			output.writeObject(superEnv);
				
			//receive, extract, and decrypt inner envelope
			env = Envelope.extractInner((Envelope)input.readObject(), sessionKey);
			Cipher AESCipherDecrypt = null ;
			IvParameterSpec iv = null;
			Key key = null;
			if(env.getObjContents().size() == 5) {
				if(env.getObjContents().get(0) == null) {
					System.err.println("Error: null text");
				}
				else if(env.getObjContents().get(1) == null) {
					System.err.println("Error: null length");
				}
				else if(env.getObjContents().get(2) == null) {
					System.err.println("Error: null key index");
				}
				else if(env.getObjContents().get(3) == null) {
					System.err.println("Error: null key version");
				}
				else if(env.getObjContents().get(4) == null) {
					System.err.println("Error: null IV");
				}
				else {
					int keyIndex = (Integer)env.getObjContents().get(2);
					int keyVersion = (Integer)env.getObjContents().get(3);
					iv = (IvParameterSpec)env.getObjContents().get(4);
					try {
						key = groupMetadata.calculateKey(keyIndex, keyVersion);
						AESCipherDecrypt = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
						AESCipherDecrypt.init(Cipher.DECRYPT_MODE, key, iv);
					} catch (Exception e) {
						e.printStackTrace();
						fos.close();
						return false;
					}
				}
			}
			else {
				System.err.println("Error: invalid number of object contents");
			}
			while (env.getMessage().compareTo("CHUNK")==0) {
				
				try {
					byte[] decryptedText = AESCipherDecrypt.doFinal((byte[])env.getObjContents().get(0));
					fos.write(decryptedText, 0, (Integer)env.getObjContents().get(1));
					System.out.printf(".");
				} catch (Exception e) {
					e.printStackTrace();
					fos.close();
					return false;
				}

				env = new Envelope("DOWNLOADF"); //Success
				output.writeObject(Envelope.buildSuper(env, sessionKey));
				env = Envelope.extractInner((Envelope)input.readObject(), sessionKey);									
			}										
			fos.close();
						
		    if(env.getMessage().compareTo("EOF")==0) {
				fos.close();
								System.out.printf("\nTransfer successful file %s\n", sourceFile);
								env = new Envelope("OK"); //Success
								output.writeObject(Envelope.buildSuper(env, sessionKey));
						}
						else {
								System.out.printf("Error reading file %s (%s)\n", sourceFile, env.getMessage());
								file.delete();
								return false;								
						}
				    }    
					 
				    else {
						System.out.printf("Error couldn't create file %s\n", destFile);
						return false;
				    }
								
			
			    } catch (IOException e1) {
			    	
			    	System.out.printf("Error couldn't create file %s\n", destFile);
			    	return false;
			    
					
				}
			    catch (ClassNotFoundException e1) {
					e1.printStackTrace();
				}
				 return true;
	}

	@SuppressWarnings("unchecked")
	public List<String> listFiles(UserToken token) {
		 try
		 {
			 Envelope message = null, e = null;
			 //Tell the server to return the member list
			 message = new Envelope("LFILES");
			 message.addObject(token); //Add requester's token
			 output.writeObject(Envelope.buildSuper(message, sessionKey)); 
			 
			 e = Envelope.extractInner((Envelope)input.readObject(), sessionKey);
			 
			 //If server indicates success, return the member list
			 if(e.getMessage().equals("OK"))
			 { 
				return (List<String>)e.getObjContents().get(0); //This cast creates compiler warnings. Sorry.
			 }
				
			 return null;
			 
		 }
		 catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return null;
			}
	}
	@SuppressWarnings("unchecked")
	public List<String> listFiles(String groupName, UserToken token) {
		 try
		 {
			 Envelope message = null, e = null;
			 //Tell the server to return the member list
			 message = new Envelope("LFILESG");
			 message.addObject(groupName); // add groupname
			 message.addObject(token); //Add requester's token
			 output.writeObject(Envelope.buildSuper(message, sessionKey)); 
			 
			 e = Envelope.extractInner((Envelope)input.readObject(), sessionKey);
			 
			 //If server indicates success, return the member list
			 if(e.getMessage().equals("OK"))
			 { 
				return (List<String>)e.getObjContents().get(0); //This cast creates compiler warnings. Sorry.
			 }
				
			 return null;
			 
		 }
		 catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return null;
			}
	}

	public boolean upload(String sourceFile, String destFile, String group,
			UserToken token, GroupMetadata groupMetadata) {
			
		if (destFile.charAt(0)!='/') {
			 destFile = "/" + destFile;
		 }
		
		try
		 {
			 
			 Envelope message = null, env = null;
			 //Tell the server to return the member list
			 message = new Envelope("UPLOADF");
			 message.addObject(destFile);
			 message.addObject(group);
			 message.addObject(token); //Add requester's token
			 message.addObject(groupMetadata);
			 output.writeObject(Envelope.buildSuper(message, sessionKey));
			
			 
			 FileInputStream fis = new FileInputStream(sourceFile);
			 
			 env = Envelope.extractInner((Envelope)input.readObject(), sessionKey);
			 
			 //If server indicates success, return the member list
			 if(env.getMessage().equals("READY"))
			 { 
				System.out.printf("Meta data upload successful\n");
				
			}
			 else {
				
				 System.out.printf("Upload failed: %s\n", env.getMessage());
				 fis.close();
				 return false;
			 }
			 
		 	IvParameterSpec iv = CipherBox.generateRandomIV();
		 	SecretKey key = groupMetadata.getCurrentKey();
		 	int keyIndex = groupMetadata.getCurrentKeyIndex();
		 	int keyVersion = groupMetadata.getCurrentKeyVer();
			 do {
				 byte[] buf = new byte[4096];
				 	if (env.getMessage().compareTo("READY")!=0) {
				 		System.out.printf("Server error: %s\n", env.getMessage());
				 		fis.close();
				 		return false;
				 	}
				 	message = new Envelope("CHUNK");
					int n = fis.read(buf); //can throw an IOException
					if (n > 0) {
						System.out.printf(".");
					} else if (n < 0) {
						System.out.println("Read error");
						fis.close();
						return false;
					}
					// encrypt to byte[] with key and IV
					Cipher AESCipherEncrypt = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
					AESCipherEncrypt.init(Cipher.ENCRYPT_MODE, key, iv);
					byte[] encryptedText = AESCipherEncrypt.doFinal(buf);
					message.addObject(encryptedText);
					message.addObject(new Integer(n));
					
					output.writeObject(Envelope.buildSuper(message, sessionKey));
					
					
					env = Envelope.extractInner((Envelope)input.readObject(), sessionKey);
					
										
			 }
			 while (fis.available()>0);		 
			 fis.close();
			 if(env.getMessage().compareTo("READY")==0)
			 { 
				message = new Envelope("EOF");
				// send the key index, key version, and IV used to encrypt the file
				message.addObject(new Integer(keyIndex));
				message.addObject(new Integer(keyVersion));
				message.addObject(iv);
				output.writeObject(Envelope.buildSuper(message, sessionKey));
				
				env = Envelope.extractInner((Envelope)input.readObject(), sessionKey);
				if(env.getMessage().compareTo("OK")==0) {
					System.out.printf("\nFile data upload successful\n");
				}
				else {
					
					 System.out.printf("\nUpload failed: %s\n", env.getMessage());
					 return false;
				 }
			}
			 else {
				 System.out.printf("Upload failed: %s\n", env.getMessage());
				 return false;
			 }
		 }catch(Exception e1)
			{
				System.err.println("Error: " + e1.getMessage());
				e1.printStackTrace(System.err);
				return false;
				}
		 return true;
	}
	
	/**
	 * attempts to securely establish a session with the file server
	 * @return true on success, false on failure
	 */
	public boolean establishSession() {
		// send the user's public symmetric key value to the file server
		// and establish a shared secret symmetric key upon receiving the file server's
		// public value
		//establishSessionKey();
		// authenticates the server by checking the server's public key
		// against the cached registry of hostname:ip to public keys
		//authenticateServer();
		
		return false;
	}

	/**
	  * establishes a shared session key by generating a shared symmetric key between
	  * the client and the server 
	  * @return	boolean
	  */
	public SecretKey establishSessionKey() {
		KeyPair keyPair = null;
		KeyAgreement keyAgreement = null;

		try {
			keyPair = DiffieHellman.genKeyPair();
			keyAgreement = DiffieHellman.genKeyAgreement(keyPair);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}

		try {
			Envelope message = null, response = null;

			//Tell the server to delete a group
			message = new Envelope("SESSIONKEY");
			message.addObject(keyPair.getPublic()); // add public value to envelope
			output.writeObject(message); 
		
			response = (Envelope)input.readObject();

			//If server indicates success, return true
			if(response.getMessage().equals("OK"))
			{
				//retrieve the file server's public value
				PublicKey fileServerPK = (PublicKey)response.getObjContents().get(0);

				// generate the shared secret key
				sessionKey = DiffieHellman.generateSecretKey(fileServerPK, keyAgreement);

				// get the server public key
				serverPublicKey = (PublicKey)response.getObjContents().get(1);
	
				return sessionKey;
			}
			
			return null;
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return null;
		}
	 }


	 public boolean issueChallenge(){

	 	try{

		 	Envelope response = null;

		 	//Generate random long to use as r1
		 	SecureRandom srand = new SecureRandom();
		 	BigInteger r1 = new BigInteger(256, srand);

		 	//Encrypt with server's public RSA key
		 	SealedObject encRSA_R1 = CipherBox.encrypt(r1, serverPublicKey);

		 	//Build an envelope with the challenge
		 	Envelope env = new Envelope("CHALLENGE");
		 	env.addObject(encRSA_R1);

		 	System.out.println("challenge env:" + env);

		 	//Send the challenge (encrypted with the session key) to server
		 	output.writeObject(Envelope.buildSuper(env, sessionKey));

		 	response = Envelope.extractInner((Envelope)input.readObject(), sessionKey);

		 	if(response.getMessage().equals("CH_RESPONSE")){

		 		BigInteger challengeAnswer = (BigInteger)response.getObjContents().get(0);

		 		if(challengeAnswer.equals(r1)){

		 			Envelope success = new Envelope("AUTH_SUCCESS");
		 			output.writeObject(Envelope.buildSuper(success, sessionKey));

		 			return true;
		 		}

		 		return false;
		 	}
		 	return false;
	 	} catch (Exception exception){

	 		return false;
	 	}

	 }

	public int authenticateFileServerRSA(
					String publicKeyPath, 
					String privateKeyPath) {
		KeyPair keyPair = RSA.loadRSA(publicKeyPath, privateKeyPath);
		serverPublicKey = requestFSPublicKey();
		ServerInfo serverInfo = new ServerInfo(sock);
		if (!lookUpFSKey(serverInfo, serverPublicKey)) {
			// Key lookup failed
			System.out.println("Look Up Failed");
			return -1;
		}
		sessionKey = signedDiffieHellman(keyPair, serverPublicKey);
		if (sessionKey == null) {
			// Signed DiffieHellman failed
			return -2;
		}
		return 0;
	}

	public PublicKey requestFSPublicKey() {
		Envelope response = null;
		try {
			Envelope env = new Envelope("REQUEST");
			System.out.println("-----Requesting Fileserver Public Key - Sending request-----");
			System.out.println(env + "\n");
			output.writeObject(env);
			response = (Envelope)input.readObject();
			System.out.println("-----Requesting Fileserver Public Key - Receiving response-----");
			System.out.println(response + "\n");
			if (response != null) {
				if (response.getMessage().equals("REQ-RESPONSE")) {
					if (response.getObjContents().size() == 1) {
						if (response.getObjContents().get(0) != null) {
							return (PublicKey)response.getObjContents().get(0);
						}
					}
				}
			}
			return null;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	  * using the server's public key retrieved from establishSessionKey,
	  * the client verifies that the file server's hostname:port match
	  * the given public key for the file server the client has cached
	  * @return	true if the public key is cached and matches the host:port
	  * for the file server, false otherwise 
	  */
	public boolean lookUpFSKey(ServerInfo serverInfo, PublicKey serverKey) {
		if (serverKey == null) {
			return false;
		}
		// check the client's file server registry for the hostname:ip
		// pairing with the corresponding public key
		ServerRegistry fsReg;
		//attempt to load serverregistry from file
		try{
			File registryFile = new File(fileserverRegistry);
			FileInputStream fis = new FileInputStream(fileserverRegistry);
			ObjectInputStream ois = new ObjectInputStream(fis);
			fsReg = (ServerRegistry)ois.readObject();
			ois.close();
			fis.close();
		}
		catch (FileNotFoundException e){
			//If file not found, make new fileserverRegistry file
			try {
				FileOutputStream fout = new FileOutputStream(fileserverRegistry);
				ObjectOutputStream oout = new ObjectOutputStream(fout);
				fsReg = new ServerRegistry();
				oout.writeObject(fsReg);
				oout.close();
				fout.close();
			} 
			catch (Exception e1) {
				e.printStackTrace();
				return false;
			}
		}
		catch (Exception e){
			e.printStackTrace();
			return false;
		}
		//retrieve cached EXPECTED public key
		cachedPublicKey = fsReg.getServerPublicKey(serverInfo);
		//compare with current key
		if(cachedPublicKey != null && cachedPublicKey.equals(serverKey)){
			return true;
		}
		return false;
	}

	/**
	 * add the server to the user's registry cache
	 * @return success/failure
	 */
	public boolean addServerToRegistry(ServerInfo serverInfo, PublicKey serverKey) {
		// retrieve the registry
		ServerRegistry fsReg;
		//attempt to load serverregistry from file
		try{
			File registryFile = new File(fileserverRegistry);
			FileInputStream fis = new FileInputStream(fileserverRegistry);
			ObjectInputStream ois = new ObjectInputStream(fis);
			fsReg = (ServerRegistry)ois.readObject();
			ois.close();
			fis.close();
		}
		catch (Exception e){
			e.printStackTrace();
			return false;
		}
		//Add server to registry
		fsReg.insertServerInfo(serverInfo, serverKey);
		//Write out to file
		try {
			FileOutputStream fout = new FileOutputStream(fileserverRegistry);
			ObjectOutputStream oout = new ObjectOutputStream(fout);
			oout.writeObject(fsReg);
			oout.close();
			fout.close();
		} 
		catch (Exception e1) {
				e1.printStackTrace();
				return false;
		}
		return true;
	}

	public SecretKey signedDiffieHellman(String a, String b) {
		KeyPair keyPair = RSA.loadRSA(a, b);
		return signedDiffieHellman(keyPair, serverPublicKey);
	}

	// Establish File connection with RSA
	public SecretKey signedDiffieHellman(KeyPair keyPair, PublicKey serverKey) {
		KeyPair DHKeyPair = null;
		KeyAgreement keyAgreement = null;
		try {
			DHKeyPair = DiffieHellman.genKeyPair();
			keyAgreement = DiffieHellman.genKeyAgreement(DHKeyPair);
			// Send message 1 Client public key
			System.out.println("-----SIGNED-DIFFIE-HELLMAN - Sending My Public Key to Server-----");
			Envelope message1 = new Envelope("SIGNED-DIFFIE-HELLMAN");
			//SealedObject encryptedKey = CipherBox.encrypt(keyPair.getPublic(), serverKey);
			//publicKeyEnv.addObject(encryptedKey);
			message1.addObject(keyPair.getPublic());
			System.out.println("Sending: ");
			System.out.println(message1 + "\n");
			output.writeObject(message1);
			// Recv the second message
			Envelope message2 = (Envelope)input.readObject();
			System.out.println("-----SIGNED-DIFFIE-HELLMAN - Receiving the Server's Diffie Hellman Keys-----");
			System.out.println("Received: ");
			System.out.println(message2 + "\n");
			if (message2 != null) {
				if (message2.getMessage().equals("SIGNED-DIFFIE-HELLMAN-2")) {
					if (message2.getObjContents().size() == 2) {
						if (message2.getObjContents().get(0) != null) {
							if (message2.getObjContents().get(1) != null) {
								//System.out.println(serverKey);
								SealedObject recvSealedHash = (SealedObject)message2.getObjContents().get(0);
								byte[] recvHash = (byte[])CipherBox.decrypt(recvSealedHash, serverKey);
								PublicKey DHServerKey = (PublicKey)message2.getObjContents().get(1);
								System.out.println("Verify that the signed hash matches the hash of the public key");
								if (Hasher.verifyHash(recvHash, DHServerKey)) {
									System.out.println("Hashes Matched");
									// Generate secretKey
									SecretKey sessionKey = DiffieHellman.generateSecretKey(DHServerKey, keyAgreement);
									System.out.println("Session Key created: " + sessionKey);
									// Make and send Message 3
									System.out.println("\n-----SIGNED-DIFFIE-HELLMAN - Sending my Diffie Hellman keys-----");
									Envelope message3 = new Envelope("SIGNED-DIFFIE-HELLMAN-3");
									byte[] hashedPublicKey = Hasher.hash(DHKeyPair.getPublic());
									SealedObject sealedKey = CipherBox.encrypt(hashedPublicKey, keyPair.getPrivate());
									message3.addObject(sealedKey);
									message3.addObject(DHKeyPair.getPublic());
									System.out.println("SENDING MESSAGE 3");
									System.out.println("Sending: \n" + message3 + "\n");
									output.writeObject(message3);
									// Recv Message 4
									Envelope message4 = Envelope.extractInner((Envelope)input.readObject(), sessionKey);
									System.out.println("-----SIGNED-DIFFIE-HELLMAN - Receiving the Success hash-----");
									System.out.println(message4 + "\n");
									if (message4 != null) {
										if (message4.getMessage().equals("SUCCESS")) {
											if (message4.getObjContents().size() == 2) {
												if (message4.getObjContents().get(0) != null) {
													if (message4.getObjContents(). get(1) != null) {
														recvHash = (byte[])message4.getObjContents().get(0);
														Integer seqNumber = (Integer)message4.getObjContents().get(1);
														sequenceNumber = seqNumber.intValue();
														System.out.println("Inital Sequence Number set to: " + sequenceNumber);
														String keyPlusServer = CipherBox.getKeyAsString(sessionKey);
														keyPlusServer = keyPlusServer + "fileserver";
														System.out.println("Verifying the received Succes hash");
														if (Hasher.verifyHash(recvHash, keyPlusServer)) {
															System.out.println("Hashes Match");
															// Send Message 5
															System.out.println("\n-----SIGNED-DIFFIE-HELLMAN - Sending my Success Hash-----");
															Envelope message5 = new Envelope("SUCCESS");
															String keyPlusName = CipherBox.getKeyAsString(sessionKey);
															keyPlusName = keyPlusName + "client";
															byte[] hashSuccess = Hasher.hash(keyPlusName);
															message5.addObject(hashSuccess);
															// Thread expects Initial Sequence Numbber + 1
															sequenceNumber++;
															message5.addObject(sequenceNumber);
															System.out.println("Sending: ");
															System.out.println(message5 + "\n");
															Envelope superMessage5 = Envelope.buildSuper(message5, sessionKey);
															output.writeObject(superMessage5);
															System.out.println("Secure and Authenticated connection with File Server extablished.");
															return sessionKey;
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
			return null;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
}

