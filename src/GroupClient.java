/* Implements the GroupClient Interface */

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.KeyAgreement;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class GroupClient extends Client implements GroupClientInterface {
	private SecretKey sessionKey;
	private int sequenceNumber;
	private String groupServerKeyPath = "groupserverpublic.key";

	static final int RSA_BIT_KEYSIZE = 2048;
		
	public GroupClient() {
		
	}
	
	//---------------------RSA Authentication Functions-------------------------

	public int setUpRSA() throws Exception {
		KeyPair keyPair = RSA.loadRSA("","");
		return shareRSA(keyPair);
	}

	public int shareRSA(KeyPair keyPair) throws Exception {
		Envelope message = new Envelope("RSAKEY");
		message.addObject(keyPair.getPublic());
		message.addObject(sequenceNumber); //add sequence number
		Envelope superE = Envelope.buildSuper(message, sessionKey);
		System.out.println(keyPair.getPublic());
		output.writeObject(superE);
		Envelope superResponse = (Envelope)input.readObject();
		Envelope response = Envelope.extractInner(superResponse, sessionKey);
		if (response.getMessage().equals("OK")) {
			if(response.getObjContents().get(0) != null){
				Integer seqNum = (Integer)message.getObjContents.get(0);
				if(seqNum == sequenceNumber + 1){
					sequenceNumber += 2;
					return 0;
				}
			}
		}
		else {
			return -1;
		}
	}

	// Login the group server with RSA
	public int authenticateGroupServerRSA(
					String username, 
					String publicKeyPath, 
					String privateKeyPath) {
		KeyPair keyPair = RSA.loadRSA(publicKeyPath, privateKeyPath);
		PublicKey serverKey = RSA.loadServerKey(groupServerKeyPath);
		sessionKey = establishSessionKeyRSA(username, keyPair, serverKey);
		if (sessionKey == null) {
			// Error creating the sharedKey
			return -1;
		}
		return 0;
	}

	// Establish key with Signed DiffieHellman
	public SecretKey establishSessionKeyRSA(
						String username, 
						KeyPair keyPair, 
						PublicKey serverKey) {
		KeyPair DHKeyPair = null;
		KeyAgreement keyAgreement = null;
		try {
			DHKeyPair = DiffieHellman.genKeyPair();
			keyAgreement = DiffieHellman.genKeyAgreement(DHKeyPair);
			byte[] hashedPublicKey = Hasher.hash(DHKeyPair.getPublic());
			SealedObject sealedKey;
			sealedKey = CipherBox.encrypt(hashedPublicKey, keyPair.getPrivate());
			// Send message 1
			Envelope message = new Envelope("RSALOGIN");
			message.addObject(username);
			message.addObject(sealedKey);
			message.addObject(DHKeyPair.getPublic());
			System.out.println("SENDING FIRST MESSAGE");
			System.out.println(message);
			output.writeObject(message);
			// Recive Message 2
			Envelope response = (Envelope)input.readObject();
			System.out.println("RECVD SEND MESSAGE");
			System.out.println(response);
			if (response != null) {
				if (response.getMessage().equals("RSALOGINOK")) {
					if (response.getObjContents().size() == 2) {
						if (response.getObjContents().get(0) != null) {
							if (response.getObjContents().get(1) != null) {
								SealedObject recvSealedHash = (SealedObject)response.getObjContents().get(0);
								byte[] recvHash = (byte[])CipherBox.decrypt(recvSealedHash, serverKey);
								PublicKey DHServerKey = (PublicKey)response.getObjContents().get(1);
								if (Hasher.verifyHash(recvHash, DHServerKey)) {
									System.out.println("MATCHING HASHES");
									SecretKey sessionKey = DiffieHellman.generateSecretKey(DHServerKey, keyAgreement);
									// Send Message 3
									Envelope innerResponse = new Envelope("SUCCESS");
									String keyPlusName = CipherBox.getKeyAsString(sessionKey);
									keyPlusName = keyPlusName + username;
									byte[] hashSuccess = Hasher.hash(keyPlusName);
									innerResponse.addObject(hashSuccess);
									SecureRandom rand = new SecureRandom();
									sequenceNumber = rand.nextInt(101);
									innerResponse.addObject(sequenceNumber);
									System.out.println("SENDING THIRD MESSAGE");
									System.out.println(innerResponse);
									response = Envelope.buildSuper(innerResponse, sessionKey);
									System.out.println("SUPER ENV FOR THIRD MESSAGE");
									System.out.println(response);
									output.writeObject(response);
									// Recive Message 4
									response = Envelope.extractInner((Envelope)input.readObject(), sessionKey);
									System.out.println("RECVD FOURTH MESSAGE");
									System.out.println(response);
									if (response != null) {
										if (response.getMessage().equals("SUCCESS")) {
											if (response.getObjContents().size() == 2) {
												if (response.getObjContents().get(0) != null) {
													if (response.getObjContents().get(1) != null) {
														recvHash = (byte[])response.getObjContents().get(0);
														Integer seqNum = (Integer)response.getObjContents().get(1);
														String keyPlusWord = CipherBox.getKeyAsString(sessionKey);
														keyPlusWord = keyPlusWord + "groupserver";
														System.out.println(keyPlusWord);
														if (Hasher.verifyHash(recvHash, keyPlusWord)) {
															if (seqNum == sequenceNumber + 1) {
																sequenceNumber += 2;
																System.out.println("SECURE AND AUTH'D CONNECTION ESTABLISHED");
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
			}
			return null;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	//------------------Post-Authentication Functionality-----------------------

	public UserToken getToken(String username) {
		try {
			UserToken token = null;
			Envelope message = null, response = null;
			Envelope superE = null, superResponse = null;	 	
			//Tell the server to return a token.
			message = new Envelope("GET");
			message.addObject(username); //Add user name string
			message.addObject(sequenceNumber) //Add sequence number
			superE = Envelope.buildSuper(message, sessionKey);
			output.writeObject(superE);
			
			//Get the response from the server
			superResponse = (Envelope)input.readObject();
			response = Envelope.extractInner(superResponse, sessionKey);			
			//Successful response
			if(response.getMessage().equals("OK")) {
				if(response.getObjContents().get(0) != null){
					if(response.getObjContents().get(1) != null){
						Integer seqNum = (Integer)response.getObjContents().get(1);
						if(seqNum == sequenceNumber + 1){

							token = (UserToken)response.getObjContents().get(0);
							sequenceNumber += 2;
							return token;
						}
					}
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

	/**
	 * retreives the meta-data for all of a user's groups
	 * i.e. old keys, current key, current key version, and the associated
	 * group name
	 * @param	user's token
	 * @return	group metadata for each group
	 */
	@SuppressWarnings("unchecked")
	public ArrayList<GroupMetadata> getGroupsMetadata(UserToken	token) {
		try {
			ArrayList<GroupMetadata> groupsmd = null;
			Envelope message = null, response = null;
			Envelope superE = null, superResponse = null;
			//Tell the server to return the user's groups meta-data.
			message = new Envelope("GET-GMETADATA");
			message.addObject(token); //Add requester's token
			message.addObject(sequenceNumber); //add sequence number
			superE = Envelope.buildSuper(message, sessionKey);
			output.writeObject(superE);
			
			//Get the response from the server
			superResponse = (Envelope)input.readObject();
			response = Envelope.extractInner(superResponse, sessionKey);			
			//Successful response
			if(response.getMessage().equals("OK")){
				if(response.getObjContents().get(0) != null){
					if(response.getObjContents().get(1) != null){
						Integer seqNum = (Integer)response.getObjContents().get(1);
						if(seqNum == sequenceNumber + 1){

							groupsmd = (ArrayList<GroupMetadata>)response.getObjContents().get(0);
							sequenceNumber += 2;
							return groupsmd;
						}
					}
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
					String publicKeyPath, 
					UserToken token) {
		try {
			//Get only public key from file
			PublicKey publicKey = RSA.loadPublic(publicKeyPath);
			//Create envelopes for transmission
			Envelope message = null, response = null;
			Envelope superE = null, superResponse = null;
			//Tell the server to create a user
			message = new Envelope("CUSER");
			message.addObject(username); //Add user name string
			message.addObject(publicKey);
			message.addObject(token); //Add the requester's token
			message.addObject(sequenceNumber); //Add sequence number
			superE = Envelope.buildSuper(message, sessionKey);
			output.writeObject(superE);
			superResponse = (Envelope)input.readObject();
			response = Envelope.extractInner(superResponse, sessionKey);
			//Check sequence number and server response message
			if (response.getObjContents().get(0) != null){
				if (response.getMessage().equals("OK")) {

					Integer seqNum = (Integer)response.getObjContents().get(0);
					if(seqNum == sequenceNumber + 1){
						sequenceNumber += 2;
						return true;
					}
				}
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
			message.addObject(sequenceNumber); //Add sequence number
			superE = Envelope.buildSuper(message, sessionKey);
			output.writeObject(superE);
			
			superResponse = (Envelope)input.readObject();
			response = Envelope.extractInner(superResponse, sessionKey);
	
			//If server indicates success, return true
			if (response.getMessage().equals("OK")) {
				if (response.getObjContents().get(0) != null){
					Integer seqNum = (Integer)response.getObjContents().get(0);
					if (seqNum == sequenceNumber + 1){
						sequenceNumber += 2;
						return true;
					}
				}
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
			message.addObject(sequenceNumber); //add sequence number
			superE = Envelope.buildSuper(message, sessionKey);
			output.writeObject(superE); 
			//System.out.println("Sent: " + message);
			
			superResponse = (Envelope)input.readObject();
			response = Envelope.extractInner(superResponse, sessionKey);

			//If server indicates success, return true
			if (response.getMessage().equals("OK")) {
				if(response.getObjContents().get(0) != null){
					Integer seqNum = (Integer)response.getObjContents().get(0);
					if(seqNum == sequenceNumber + 1){
						sequenceNumber += 2;
						return true;
					}
				}
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
			message.addObject(sequenceNumber); //add sequence number
			superE = Envelope.buildSuper(message, sessionKey);
			output.writeObject(superE); 
			
			superResponse = (Envelope)input.readObject();
			response = Envelope.extractInner(superResponse, sessionKey);
			//If server indicates success, return true
			if (response.getMessage().equals("OK")) {
				if(response.getObjContents().get(0) != null){
					Integer seqNum = (Integer)response.getObjContents().get(0);
					if(seqNum == sequenceNumber + 1){
						sequenceNumber += 2;
						return true;
					}
				}
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
			message.addObject(sequenceNumber); //Add seq num
			superE = Envelope.buildSuper(message, sessionKey);
			output.writeObject(superE); 
			 
			superResponse = (Envelope)input.readObject();
			response = Envelope.extractInner(superResponse, sessionKey);

			//If server indicates success, return the m)ember list
			if (response.getMessage().equals("OK")) { 
				if(response.getObjContents().get(0) != null){
					if(response.getObjContents().get(1) != null){
						Integer seqNum = (Integer)response.getObjContents().get(1);
						if(seqNum == sequenceNumber + 1){
							sequenceNumber += 2;
							return (List<String>)response.getObjContents().get(0); //This cast creates compiler warnings
						}
					}
				}
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
			message.addObject(sequenceNumber); //add seq num
			superE = Envelope.buildSuper(message, sessionKey);
			output.writeObject(superE); 
			
			superResponse = (Envelope)input.readObject();
			response = Envelope.extractInner(superResponse, sessionKey);
			//If server indicates success, return true
			if (response.getMessage().equals("OK")) {
				if (response.getObjContents().get(0) != null){
					Integer seqNum = (Integer)response.getObjContents().get(1);
					if(seqNum == sequenceNumber + 1){
						sequenceNumber += 2;
						return true;
					}
				}
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
			message.addObject(sequenceNumber); //add seq num
			superE = Envelope.buildSuper(message, sessionKey);
			output.writeObject(superE);
			
			superResponse = (Envelope)input.readObject();
			response = Envelope.extractInner(superResponse, sessionKey);
			//If server indicates success, return true
			if (response.getMessage().equals("OK")) {
				if (response.getObjContents().get(0) != null){
					Integer seqNum = (Integer)response.getObjContents().get(1);
					if(seqNum == sequenceNumber + 1){
						sequenceNumber += 2;
						return true;
					}
				}
			}
				
			return false;
		}
		catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	}

	public void disconnect() {
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


	//Passwords are now unused in Phase 4. All code below pertaining to passwords is no longer used.

	/*
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
		Envelope message = Envelope.buildSuper(contents, sessionKey);
		output.writeObject(message);
		Envelope superResponse = (Envelope)input.readObject();
		Envelope response = Envelope.extractInner(superResponse, sessionKey);
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
			Envelope message = Envelope.buildSuper(contents, sessionKey);
			output.writeObject(message);
			Envelope superResponse = (Envelope)input.readObject();
			Envelope response = Envelope.extractInner(superResponse, sessionKey);
			if (response.getMessage().equals("OK")) {
				return true;
			}
			return false;
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
	}

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
	*/


}
