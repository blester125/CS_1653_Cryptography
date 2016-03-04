/* Implements the GroupClient Interface */

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.io.ObjectInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.security.SecureRandom;
import javax.crypto.spec.IvParameterSpec;

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

public class GroupClient extends Client implements GroupClientInterface {
	private SecretKey sessionKey;

	static final int RSA_BIT_KEYSIZE = 2048;
	
	public GroupClient() {
		
	}

	private Envelope buildSuper(Envelope env){

		IvParameterSpec ivspec = CipherBox.generateRandomIV();			
		Envelope superEnv = new Envelope("SUPER");
		superEnv.addObject(CipherBox.encrypt(env, sessionKey, ivspec));
		superEnv.addObject(ivspec.getIV());
		return superEnv;
	}

	private Envelope extractInner(Envelope superInputEnv){

		SealedObject innerEnv = (SealedObject)superInputEnv.getObjContents().get(0);
		IvParameterSpec decIVSpec = new IvParameterSpec((byte[])superInputEnv.getObjContents().get(1));
		Envelope env = (Envelope)CipherBox.decrypt(innerEnv, sessionKey, decIVSpec);
		return env;
	}

	public void disconnect()	 {
		if (isConnected()) {
			try {
				Envelope message = new Envelope("DISCONNECT");
				Envelope superE = buildSuper(message);
				output.writeObject(superE);
				sock.close(); //close the socket
			}
			catch(Exception e) {
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
			}
		}
	}

	public int authenticateGroupServer(String username, String password) throws Exception {
		sessionKey = establishSessionKey();
		if (sessionKey == null) {
			// Unable to make the sessionKey();
			return -1;
		}
		return login(username, password);
	}

	public int login(String username, String password) throws Exception 
	{
		Envelope contents = new Envelope("LOGIN");
		contents.addObject(username);
		contents.addObject(password);
		Envelope message = buildSuper(contents);
		output.writeObject(message);
		Envelope superResponse = (Envelope)input.readObject();
		Envelope response = extractInner(superResponse);
		if (response.getMessage().equals("OK")) {
			return 0;
		}
		else if (response.getMessage().equals("CHANGEPASSWORD")) {
			return 1;
		}
		else 
		{
			// Error Authinticating
			return -2;
		}
 	}

 	public boolean newPassword(String password) {
 		try {
	 		Envelope contents = new Envelope("CHANGEPASSWORD");
 			contents.addObject(password);
 			Envelope message = buildSuper(contents);
	 		output.writeObject(message);
 			Envelope superResponse = (Envelope)input.readObject();
 			Envelope response = extractInner(superResponse);
 			if (response.getMessage().equals("OK")) {
	 			return true;
 			}
 			return false;
 		} catch (Exception e) {
 			e.printStackTrace();
 			return false;
 		}
 	}
 
	public UserToken getToken(String username) {
		try {
			UserToken token = null;
			Envelope message = null, response = null;
			Envelope superE = null, superResponse = null;	 	
			//Tell the server to return a token.
			message = new Envelope("GET");
			message.addObject(username); //Add user name string
			superE = buildSuper(message);
			output.writeObject(superE);
			
			//Get the response from the server
			superResponse = (Envelope)input.readObject();
			response = extractInner(superResponse);			
			//Successful response
			if(response.getMessage().equals("OK"))
			{
				//If there is a token in the Envelope, return it 
				ArrayList<Object> temp = null;
				temp = response.getObjContents();
				if(temp.size() == 1)
				{
					token = (UserToken)temp.get(0);
					return token;
				}
			}
			return null;
		}
		catch(Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return null;
		}
		
	 }
	 
	public boolean createUser(
					String username, 
					String password, 
					UserToken token) {
		try {
			Envelope message = null, response = null;
			Envelope superE = null, superResponse = null;
			//Tell the server to create a user
			message = new Envelope("CUSER");
			message.addObject(username); //Add user name string
			message.addObject(password);
			message.addObject(token); //Add the requester's token
			superE = buildSuper(message);
			output.writeObject(superE);
			superResponse = (Envelope)input.readObject();
			response = extractInner(superResponse);
			//If server indicates success, return true
			if (response.getMessage().equals("OK")) {
				return true;
			}
			return false;
		}
		catch(Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	}
	
	public boolean deleteUser(String username, UserToken token) {
		try {
			Envelope message = null, response = null;
			Envelope superE = null, superResponse = null;
			//Tell the server to delete a user
			message = new Envelope("DUSER");
			message.addObject(username); //Add user name
			message.addObject(token);  //Add requester's token
			superE = buildSuper(message);
			output.writeObject(superE);
			
			superResponse = (Envelope)input.readObject();
			response = extractInner(superResponse);
	
			//If server indicates success, return true
			if (response.getMessage().equals("OK")) {
				return true;
			}
				
			return false;
		}
		catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	}
	
	public boolean createGroup(String groupname, UserToken token) {
		try {
			Envelope message = null, response = null;
			Envelope superE = null, superResponse = null;
			//Tell the server to create a group
			message = new Envelope("CGROUP");
			message.addObject(groupname); //Add the group name string
			message.addObject(token); //Add the requester's token
			superE = buildSuper(message);
			output.writeObject(superE); 
			//System.out.println("Sent: " + message);
			
			superResponse = (Envelope)input.readObject();
			response = extractInner(superResponse);

			//If server indicates success, return true
			if (response.getMessage().equals("OK")) {
				return true;
			}
				
			return false;
		}
		catch(Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	}

	public boolean deleteGroup(String groupname, UserToken token) {
		try {
			Envelope message = null, response = null;
			Envelope superE = null, superResponse = null;
			//Tell the server to delete a group
			message = new Envelope("DGROUP");
			message.addObject(groupname); //Add group name string
			message.addObject(token); //Add requester's token
			superE = buildSuper(message);
			output.writeObject(superE); 
			
			superResponse = (Envelope)input.readObject();
			response = extractInner(superResponse);
			//If server indicates success, return true
			if (response.getMessage().equals("OK")) {
				return true;
			}
				
			return false;
		}
		catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	}

	@SuppressWarnings("unchecked")
	public List<String> listMembers(String group, UserToken token) {
		try {
		 	output.flush();
		 	output.reset();

			Envelope message = null, response = null;
			Envelope superE = null, superResponse = null;
			//Tell the server to return the member list
			message = new Envelope("LMEMBERS");
			message.addObject(group); //Add group name string
			message.addObject(token); //Add requester's token
			superE = buildSuper(message);
			output.writeObject(superE); 
			 
			superResponse = (Envelope)input.readObject();
			response = extractInner(superResponse);

			//If server indicates success, return the member list
			if (response.getMessage().equals("OK")) { 
				return (List<String>)response.getObjContents().get(0); //This cast creates compiler warnings. Sorry.
			}
				
			return null;
			 
		}
		catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return null;
		}
	}

	public boolean addUserToGroup(
					String username, 
					String groupname, 
					UserToken token) {
		try {
			Envelope message = null, response = null;
			Envelope superE = null, superResponse = null;
			//Tell the server to add a user to the group
			message = new Envelope("AUSERTOGROUP");
			message.addObject(username); //Add user name string
			message.addObject(groupname); //Add group name string
			message.addObject(token); //Add requester's token
			superE = buildSuper(message);
			output.writeObject(superE); 
			
			superResponse = (Envelope)input.readObject();
			response = extractInner(superResponse);
			//If server indicates success, return true
			if (response.getMessage().equals("OK")) {
					return true;
			}
			
			return false;
		}
		catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	}
	
	public boolean deleteUserFromGroup(
						String username, 
	 					String groupname, 
	 					UserToken token) {
		try {
			Envelope message = null, response = null;
			Envelope superE = null, superResponse = null;
			//Tell the server to remove a user from the group
			message = new Envelope("RUSERFROMGROUP");
			message.addObject(username); //Add user name string
			message.addObject(groupname); //Add group name string
			message.addObject(token); //Add requester's token
			superE = buildSuper(message);
			output.writeObject(superE);
			
			superResponse = (Envelope)input.readObject();
			response = extractInner(superResponse);
			//If server indicates success, return true
			if (response.getMessage().equals("OK")) {
				return true;
			}
				
			return false;
		}
		catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	}

	/**
	 * establishes a shared session key by generating a shared symmetric key between
	 * the client and the server 
	 * @return	SecretKey on success, null on failure
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
			message = new Envelope("SESSIONKEY");
			message.addObject(keyPair.getPublic()); // add public value to envelope
			output.writeObject(message); 
		
			response = (Envelope)input.readObject();
			//If server indicates success, return true
			if (response.getMessage().equals("OK")) {
				//retrieve the group server's public value
				PublicKey groupServerPK = (PublicKey)response.getObjContents().get(0);
				// generate the shared secret key
				SecretKey secretKey = DiffieHellman.generateSecretKey(groupServerPK, keyAgreement);
				System.out.println(new String(secretKey.getEncoded()));
	
				return secretKey;
			}
			
			return null;
		}
		catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return null;
		}
	}

	public String setUpRSA() {
		KeyPair keyPair = loadRSA();
		return shareRSA(keyPair);
	}

	public KeyPair loadRSA() {
		//Attempt to load RSA key pair from file
		try{
			KeyPair rsaPair;
			File fsPublicKey = new File("userpublic.key");
			FileInputStream keyIn = new FileInputStream("userpublic.key");
			byte[] encPublicKey = new byte[(int) fsPublicKey.length()];
			keyIn.read(encPublicKey);
			keyIn.close();

			File fsPrivateKey = new File("userprivate.key");
			keyIn = new FileInputStream("userprivate.key");
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
			return rsaPair;
		}
		catch (FileNotFoundException e) {
			try {
				System.out.println("Did not find public and/or private RSA keys. Generating new key pair....");
			
				//Generate RSA key pair with KeyPairGenerator, 1024 bits
				KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
				keyGen.initialize(RSA_BIT_KEYSIZE);
				KeyPair rsaPair = keyGen.generateKeyPair();
				PrivateKey privateKey = rsaPair.getPrivate();
				PublicKey publicKey = rsaPair.getPublic();

				//Store both keys to file
				X509EncodedKeySpec x590keyspec = new X509EncodedKeySpec(publicKey.getEncoded());
				FileOutputStream keyOut = new FileOutputStream("userpublic.key");
				keyOut.write(x590keyspec.getEncoded());
				keyOut.close();

				PKCS8EncodedKeySpec pkcs8keyspec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
				keyOut = new FileOutputStream("userprivate.key");
				keyOut.write(pkcs8keyspec.getEncoded());
				keyOut.close();

				System.out.println("New RSA key pair generated and stored!");
				return rsaPair;
			}
			catch (Exception f){
				System.out.println("Exception thrown in create new RSA pair.");
				return null;
			}

		}
		catch (IOException e) {
			System.out.println("Could not read or write from/to key files!");
			return null;
		}
		catch (NoSuchAlgorithmException e){
			System.out.println("Algorithm does not exist!");
			return null;
		}
		catch (InvalidKeySpecException e){
			System.out.println("Invalid key specification!");
			return null;
		}
		catch (Exception e){
			System.out.println("unspecified exception thrown");
			return null;
		}
	}

	public String shareRSA(KeyPair keypair) {
		// Send rsa public key
		return "";
	}

	public String authenticateGroupServerRSA() {
		sessionKey = establishSessionKeyRSA();
		if (sessionKey == null) {
			return "Error Authenticating with the Group Server.";
		}
		return "OK";
	}

	public SecretKey establishSessionKeyRSA() {
		return null;
	}
}
