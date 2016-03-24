/* FileClient provides all the client functionality regarding the file server */

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.List;

import javax.crypto.KeyAgreement;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class FileClient extends Client implements FileClientInterface {
	private SecretKey secretKey;
	public PublicKey cachedPublicKey;
	private String fileserverRegistry = "FileServerRegistry.bin";
	public PublicKey serverPublicKey = null;
	public String cachedKeyFingerprint;
	public String serverKeyFingerprint;
	
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
				Envelope superE = Envelope.buildSuper(message, secretKey);
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
			Envelope superEnv = Envelope.buildSuper(env, secretKey);
			output.writeObject(superEnv);

			//receive, extract, and decrypt inner envelope
			env = Envelope.extractInner((Envelope)input.readObject(), secretKey);
		   
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

	public boolean download(String sourceFile, String destFile, String group, UserToken token) {
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
			Envelope superEnv = Envelope.buildSuper(env, secretKey);
			output.writeObject(superEnv); 
				
			//receive, extract, and decrypt inner envelope
			env = Envelope.extractInner((Envelope)input.readObject(), secretKey);
				    
			while (env.getMessage().compareTo("CHUNK")==0) { 
				fos.write((byte[])env.getObjContents().get(0), 0, (Integer)env.getObjContents().get(1));
				System.out.printf(".");

				env = new Envelope("DOWNLOADF"); //Success
				output.writeObject(Envelope.buildSuper(env, secretKey));
				env = Envelope.extractInner((Envelope)input.readObject(), secretKey);									
			}										
			fos.close();
						
		    if(env.getMessage().compareTo("EOF")==0) {
				fos.close();
								System.out.printf("\nTransfer successful file %s\n", sourceFile);
								env = new Envelope("OK"); //Success
								output.writeObject(Envelope.buildSuper(env, secretKey));
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
			 output.writeObject(Envelope.buildSuper(message, secretKey)); 
			 
			 e = Envelope.extractInner((Envelope)input.readObject(), secretKey);
			 
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
			 output.writeObject(Envelope.buildSuper(message, secretKey)); 
			 
			 e = Envelope.extractInner((Envelope)input.readObject(), secretKey);
			 
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
			UserToken token) {
			
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
			 output.writeObject(Envelope.buildSuper(message, secretKey));
			
			 
			 FileInputStream fis = new FileInputStream(sourceFile);
			 
			 env = Envelope.extractInner((Envelope)input.readObject(), secretKey);
			 
			 //If server indicates success, return the member list
			 if(env.getMessage().equals("READY"))
			 { 
				System.out.printf("Meta data upload successful\n");
				
			}
			 else {
				
				 System.out.printf("Upload failed: %s\n", env.getMessage());
				 return false;
			 }
			 
		 	
			 do {
				 byte[] buf = new byte[4096];
				 	if (env.getMessage().compareTo("READY")!=0) {
				 		System.out.printf("Server error: %s\n", env.getMessage());
				 		return false;
				 	}
				 	message = new Envelope("CHUNK");
					int n = fis.read(buf); //can throw an IOException
					if (n > 0) {
						System.out.printf(".");
					} else if (n < 0) {
						System.out.println("Read error");
						return false;
					}
					
					message.addObject(buf);
					message.addObject(new Integer(n));
					
					output.writeObject(Envelope.buildSuper(message, secretKey));
					
					
					env = Envelope.extractInner((Envelope)input.readObject(), secretKey);
					
										
			 }
			 while (fis.available()>0);		 
					 
			 //If server indicates success, return the member list
			 if(env.getMessage().compareTo("READY")==0)
			 { 
				
				message = new Envelope("EOF");
				output.writeObject(Envelope.buildSuper(message, secretKey));
				
				env = Envelope.extractInner((Envelope)input.readObject(), secretKey);
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
		establishSessionKey();
		// authenticates the server by checking the server's public key
		// against the cached registry of hostname:ip to public keys
		authenticateServer();
		
		return false;
	}

	/**
	  * using the server's public key retrieved from establishSessionKey,
	  * the client verifies that the file server's hostname:port match
	  * the given public key for the file server the client has cached
	  * @return	true if the public key is cached and matches the host:port
	  * for the file server, false otherwise 
	  */
	public boolean authenticateServer() {
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
		cachedPublicKey = fsReg.getServerPublicKey(new ServerInfo(this.sock.getInetAddress().getHostName(), Integer.toString(this.sock.getPort())));

		//compare with current key
		if(cachedPublicKey != null && cachedPublicKey.equals(serverPublicKey)){
			return true;
		}

		
		return false;
	}
	
	/**
	 * add the server to the user's registry cache
	 * @return success/failure
	 */
	public boolean addServerToRegistry() {
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
		fsReg.insertServerInfo(new ServerInfo(this.sock.getInetAddress().getHostName(), Integer.toString(this.sock.getPort())), this.serverPublicKey);

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
				secretKey = DiffieHellman.generateSecretKey(fileServerPK, keyAgreement);

				// get the server public key
				serverPublicKey = (PublicKey)response.getObjContents().get(1);
	
				return secretKey;
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
		 	output.writeObject(Envelope.buildSuper(env, secretKey));

		 	response = Envelope.extractInner((Envelope)input.readObject(), secretKey);

		 	if(response.getMessage().equals("CH_RESPONSE")){

		 		BigInteger challengeAnswer = (BigInteger)response.getObjContents().get(0);

		 		if(challengeAnswer.equals(r1)){

		 			Envelope success = new Envelope("AUTH_SUCCESS");
		 			output.writeObject(Envelope.buildSuper(success, secretKey));

		 			return true;
		 		}

		 		return false;
		 	}
		 	return false;
	 	} catch (Exception exception){

	 		return false;
	 	}

	 }

	 public void generateFingerprints(){

	 	cachedKeyFingerprint = javax.xml.bind.DatatypeConverter.printHexBinary(Hasher.hash(cachedPublicKey));
	 	serverKeyFingerprint = javax.xml.bind.DatatypeConverter.printHexBinary(Hasher.hash(serverPublicKey));

	 }
}

