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

/* Implements the GroupClient Interface */

import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.KeyAgreement;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;

import java.io.*;
import org.apache.commons.codec.binary.Base32;

public class GroupClient extends Client implements GroupClientInterface {
	private SecretKey sessionKey;
	private int sequenceNumber;
	private String groupServerKeyPath = "groupserverpublic.key";
	private PublicKey groupServerKey;

	static final int RSA_BIT_KEYSIZE = 2048;
		
	public GroupClient() {
		
	}

	public PublicKey getGroupServerKey() {
		return groupServerKey;
	}

/*---------------------RSA Authentication Functions---------------------------*/
	/**
	 * Loads RSA public key and tries to share it with the server.
	 * @param publicPath: The path to the file that contains the new 
	 *                    public key.
	 * @return -1 on failure to load the publicKey, 
	 *          0 on success
	 */
	public int setUpRSA(String publicPath) {
		PublicKey newKey = RSA.loadServerKey(publicPath);
		if (newKey == null) {
			return -1;
		}
		return shareRSA(newKey);
	}

	/**
	 * Sends the PublicKey to the server where it is set as the RSA
	 * key used to authenticate the logged in user.
	 * @param newKey: The Key that will be used to authenticate the user.
	 * @return -2 on malformed message from the server.
	 *          0 on success
	 */
	public int shareRSA(PublicKey newKey) {
		try {
			// Add token to this
			Envelope message = new Envelope("RSAKEY");
			message.addObject(newKey);
			message.addObject(sequenceNumber); //add sequence number
			Envelope superE = Envelope.buildSuper(message, sessionKey);
			output.writeObject(superE);
			Envelope superResponse = (Envelope)input.readObject();
			Envelope response = Envelope.extractInner(superResponse, sessionKey);
			System.out.println(response);
			if (response != null) {
				if (response.getMessage().equals("OK")) {
					if (response.getObjContents().size() == 1) {
						if(response.getObjContents().get(0) != null){
							Integer seqNum = (Integer)response.getObjContents().get(0);
							if(seqNum == sequenceNumber + 1){
								sequenceNumber += 2;
								return 0;
							}
						}
					}
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return -2;
	}

	/**
	 * Login to the groupserver using RSA. 
	 * @param username: The name of the user that is loggin in
	 * @param publicKeyPath: The filepath of the public key for this user.
	 * @param privateKeyPath: The filepath of the private key for this user.
	 * @return -1 on failure to load the group server key.
	 *         -2 on failure to establish the session key.
	 *          0 on success. 
	 */
	public int authenticateGroupServerRSA(
					String username, 
					String publicKeyPath, 
					String privateKeyPath) throws TwoFactorException {
		KeyPair keyPair = RSA.loadRSA(publicKeyPath, privateKeyPath);
		// This always return a keyPair even if it has to make one that is 
		// saved into the two file paths.
		groupServerKey = RSA.loadServerKey(groupServerKeyPath);
		if (groupServerKey == null) {
			return -1;
		}
		try {
			Envelope puzzleAnswer = solvePuzzle();
			if (puzzleAnswer == null) {
				return -3;
			}
			if (puzzleAnswer.getObjContents().size() != 2) {
				return -3;
			}
			if (puzzleAnswer.getObjContents().get(0) == null) {
				return -3;
			}
			if (puzzleAnswer.getObjContents().get(1) == null) {
				return -3;
			}
			boolean check = establishSessionKeyRSA(
								username, 
								keyPair, 
								groupServerKey,
								puzzleAnswer);
			if (check == false) {
				// Error creating the sharedKey
				return -2;
			}
		} catch (TwoFactorException e) {
			throw e;
		}
		return 0;
	}

	/** 
	 * Establish a session key with Signed DiffieHellman.
	 * @param username: The name of the user attempting to log in.
	 * @param keyPair: The public and private key that will be used by the user.
	 * @param serverKey: The public key that will used to verify the servers messages.
	 * @return secretKey on success and null on failure.
	 */
	public boolean establishSessionKeyRSA(
						String username, 
						KeyPair keyPair, 
						PublicKey serverKey,
						Envelope puzzleAnswer) throws TwoFactorException {
		KeyPair DHKeyPair = null;
		KeyAgreement keyAgreement = null;
		try {
			DHKeyPair = DiffieHellman.genKeyPair();
			keyAgreement = DiffieHellman.genKeyAgreement(DHKeyPair);
			byte[] hashedPublicKey = Hasher.hash(DHKeyPair.getPublic());
			SealedObject sealedKey;
			sealedKey = CipherBox.encrypt(hashedPublicKey, keyPair.getPrivate());
			// Send message 1
			System.out.println("-----SIGNED-DIFFIE-HELLMAN - Sending my Diffie Hellman Public Keys-----");
			Envelope message1 = new Envelope("RSALOGIN");
			message1.addObject(username);
			message1.addObject(sealedKey);
			message1.addObject(DHKeyPair.getPublic());
			message1.addObject(puzzleAnswer.getObjContents().get(0));
			message1.addObject(puzzleAnswer.getObjContents().get(1));
			System.out.println("Sending:");
			System.out.println(message1 + "\n");
			output.writeObject(message1);
			// Recive Message 2
			System.out.println("-----SIGNED-DIFFIE-HELLMAN - Receiving group server Diffie Hellman Public Keys-----");
			Envelope message2 = (Envelope)input.readObject();
			System.out.println("Received:");
			System.out.println(message2 + "\n");
			if (message2 != null) {
				if (message2.getMessage().equals("RSALOGINOK")) {
					if (message2.getObjContents().size() == 2) {
						if (message2.getObjContents().get(0) != null) {
							if (message2.getObjContents().get(1) != null) {
								SealedObject recvSealedHash = (SealedObject)message2.getObjContents().get(0);
								byte[] recvHash = (byte[])CipherBox.decrypt(recvSealedHash, serverKey);
								PublicKey DHServerKey = (PublicKey)message2.getObjContents().get(1);
								System.out.println("Verify the signed hash matchs the generated hash");
								if (Hasher.verifyHash(recvHash, DHServerKey)) {
									System.out.println("Hashes Match");
									sessionKey = DiffieHellman.generateSecretKey(DHServerKey, keyAgreement);
									SecretKey confidentialityKey = KeyBox.generateConfidentialityKey(sessionKey);
									SecretKey integrityKey = KeyBox.generateIntegrityKey(sessionKey);
									System.out.println("Generated Session Key: " + KeyBox.getKeyAsString(sessionKey));
									System.out.println("Generated Confidentiality Key: " + KeyBox.getKeyAsString(confidentialityKey));
									System.out.println("Generated Integrity Key: " + KeyBox.getKeyAsString(integrityKey));
									// Send Message 3
									System.out.println("-----SIGNED-DIFFIE-HELLMAN - Sending Success Hash and Inital Sequence Number-----");
									Envelope message3 = new Envelope("SUCCESS");
									String keyPlusName = KeyBox.getKeyAsString(sessionKey);
									keyPlusName = keyPlusName + username;
									byte[] hashSuccess = Hasher.hash(keyPlusName);
									message3.addObject(hashSuccess);
									SecureRandom rand = new SecureRandom();
									sequenceNumber = rand.nextInt(101);
									System.out.println("Inital Sequence number set to: " + sequenceNumber);
									message3.addObject(sequenceNumber);
									System.out.println("Sending: ");
									System.out.println(message3 + "\n");
									Envelope superMessage3 = Envelope.buildSuper(message3, sessionKey);
									output.writeObject(superMessage3);
									// Recive Message 4
									Envelope message4 = Envelope.extractInner((Envelope)input.readObject(), sessionKey);
									System.out.println("-----SIGNED-DIFFIE-HELLMAN - Receiving the Success Hash-----");
									System.out.println("Received: ");
									System.out.println(message4 + "\n");
									// Figure out what to return for two factor.
									if (message4 != null) {
										if (message4.getMessage().equals("SUCCESS") || message4.getMessage().equals("TWO-FACTOR")) {
											if (message4.getObjContents().size() == 2) {
												if (message4.getObjContents().get(0) != null) {
													if (message4.getObjContents().get(1) != null) {
														recvHash = (byte[])message4.getObjContents().get(0);
														Integer seqNum = (Integer)message4.getObjContents().get(1);
														String keyPlusWord = KeyBox.getKeyAsString(sessionKey);
														keyPlusWord = keyPlusWord + "groupserver";
														System.out.println("Verify that the Success Hashs matchs");
														if (Hasher.verifyHash(recvHash, keyPlusWord)) {
															System.out.println("Hashes Match");
															System.out.println("Checking Sequence Number");
															if (seqNum == sequenceNumber + 1) {
																System.out.println("Sequence Number is correct.");
																sequenceNumber += 2;
																System.out.println("Sequence Number set to: " + sequenceNumber);
																if (message4.getMessage().equals("SUCCESS")) {
																	System.out.println("\nSecure and Authenticated connection with group server Established.");
																	return true;
																} else {
																	throw new TwoFactorException();
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
			}
			return false;
		} catch (IOException e) {
			e.printStackTrace();
			return false;
		}
		catch (ClassNotFoundException e) {
			e.printStackTrace();
			return false;
		}
	}

	public boolean twoFactor(String username, String code) {
		Envelope message = new Envelope("TWO-FACTOR");
		message.addObject(username);
		message.addObject(code);
		message.addObject(sequenceNumber);
		Envelope superE = Envelope.buildSuper(message, sessionKey);
		Envelope superR = null;
		try {
			output.writeObject(superE);
			superR = (Envelope)input.readObject(); 
		} catch (Exception e) {
			return false;
		}
		Envelope response = Envelope.extractInner(superR, sessionKey);
		System.out.println(response);
		if (response != null) {
			if (response.getMessage().equals("OK")) {
				if (response.getObjContents().size() == 1) {
					if (response.getObjContents().get(0) != null) {
						int temp = (Integer)response.getObjContents().get(0);
						if (temp == sequenceNumber + 1) {
							sequenceNumber += 2;
							System.out.println("\nSecure and Authenticated connection with group server Established.");
							return true;
						}
					}
				}
			}
		}
		return false;
	}

/*------------------Post-Authentication Functionality-------------------------*/
	/**
	 * Get a token from the group server that will be used on the server that 
	 * has the private key that will has the corrisponding private key.
	 * @param username: The name of the requester of the token.
	 * @param serverKey: The server key that will be put into the token.
	 * @return a token on success and null on failure. 
	 */
	public UserToken getToken(String username, PublicKey serverKey) {
		try {
			UserToken token = null;
			Envelope message = null, response = null;
			Envelope superE = null, superResponse = null;	 	
			//Tell the server to return a token.
			message = new Envelope("GET");
			message.addObject(username); //Add user name string
			message.addObject(serverKey);
			message.addObject(sequenceNumber); //Add sequence number
			superE = Envelope.buildSuper(message, sessionKey);
			output.writeObject(superE);
			
			//Get the response from the server
			superResponse = (Envelope)input.readObject();
			response = Envelope.extractInner(superResponse, sessionKey);			
			//Successful response
			if (response != null) {
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
	 * @return	group metadata for each group and null on failure.
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
			if (response != null) {
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
	 * Create a user on the group server.
	 * @param username: The name of the user that will be created.
	 * @param publicKeypath: The path to the file that has the users public key.
	 * @param token: The token that is used to check the requester permissions.
	 * @return -1 on failure to load publicKey
	 *         -2 on malformed message from the server
	 *          0 on success.
	 */
	public int createUser(
					String username, 
					String publicKeyPath, 
					UserToken token) {
		try {
			//Get only public key from file
			PublicKey publicKey = RSA.loadServerKey(publicKeyPath);
			if (publicKey == null) {
				return -1;
			}
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
			if (response != null) {
				if (response.getObjContents().get(0) != null){
					if (response.getMessage().equals("OK")) {
						Integer seqNum = (Integer)response.getObjContents().get(0);
						if(seqNum == sequenceNumber + 1){
							sequenceNumber += 2;
							return 0;
						}
					}
				}
			}
			return -2;
		}
		catch(Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return -2;
		}
	}
	
	/**
	 * Delete a user from the group server.
	 * @param username: The name of the user that is to be deleted
	 * @param token: The token that is checked for user permissions.
	 * @return true on success and false on failure.
	 */
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
			if (response != null) {
				if (response.getMessage().equals("OK")) {
					if (response.getObjContents().get(0) != null){
						Integer seqNum = (Integer)response.getObjContents().get(0);
						if (seqNum == sequenceNumber + 1){
							sequenceNumber += 2;
							return true;
						}
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
	
	/**
	 * Create a group on the group server.
	 * @param groupname: The name of the group that is to be created.
	 * @param token: The token that is checked for user permissions.
	 * @return True on success, false on failure.
	 */
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
			if (response != null) {
				if (response.getMessage().equals("OK")) {
					if(response.getObjContents().get(0) != null){
						Integer seqNum = (Integer)response.getObjContents().get(0);
						if(seqNum == sequenceNumber + 1){
							sequenceNumber += 2;
							return true;
						}
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

	/**
	 * Delete a group on the group server, if you are the owner.
	 * @param groupname: The name of the group that is to be delete.
	 * @param token: The token that is checked for user permissions.
	 * @return True on success, false on failure.
	 */
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
			if (response != null) {
				if (response.getMessage().equals("OK")) {
					if(response.getObjContents().get(0) != null){
						Integer seqNum = (Integer)response.getObjContents().get(0);
						if(seqNum == sequenceNumber + 1){
							sequenceNumber += 2;
							return true;
						}
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

	/**
	 * List the members in a group if you are the owner.
	 * @param group: The name of the group to list.
	 * @param token: The token that is used to check user permissions.
	 * @return a list of Strings on success, null on failure
	 */
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
			if (response != null) {
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
			}
			return null;
		}
		catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return null;
		}
	}

	/**
	 * Add a user to the group if you are the owner of the group.
	 * @param username: The name of the user to be added.
	 * @param groupname: The name of the group to add the user to.
	 * @param token: The token used to check premissions.
	 * @return True on Success, False on failure.
	 */
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
			if (response != null) {
				if (response.getMessage().equals("OK")) {
					if (response.getObjContents().get(0) != null){
						Integer seqNum = (Integer)response.getObjContents().get(0);
						if(seqNum == sequenceNumber + 1){
							sequenceNumber += 2;
							return true;
						}
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
	
	/**
	 * Delete a user to the group if you are the owner of the group.
	 * @param username: The name of the user to be deleted.
	 * @param groupname: The name of the group to delete the user from.
	 * @param token: The token used to check premissions.
	 * @return True on Success, False on failure.
	 */
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
			if (response != null) {
				if (response.getMessage().equals("OK")) {
					if (response.getObjContents().get(0) != null){
						Integer seqNum = (Integer)response.getObjContents().get(0);
						if(seqNum == sequenceNumber + 1){
							sequenceNumber += 2;
							return true;
						}
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

	public String enable2FactorAuthentication(UserToken token) {
		KeyPair twoFactorkeyPair = null;
		KeyAgreement twoFactorkeyAgreement = null;
		try {
			twoFactorkeyPair = DiffieHellman.genKeyPair();
			twoFactorkeyAgreement = DiffieHellman.genKeyAgreement(twoFactorkeyPair);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
		try {
			Envelope message = null, response = null;
			message = new Envelope("ENABLE-TWO-FACTOR");
			//message.addObject(twoFactorkeyPair.getPublic()); // add public value to envelope
			message.addObject(token);
			message.addObject(sequenceNumber);
			Envelope superE = Envelope.buildSuper(message, sessionKey);
			output.writeObject(superE); 
			Envelope superResponse = (Envelope)input.readObject();
			response = Envelope.extractInner(superResponse, sessionKey);
			System.out.println(response);
			if (response != null) {
				//If server indicates success, return true
				if (response.getMessage().equals("ENABLE-TWO-FACTOR-2")) {
					if (response.getObjContents().size() == 2) {
						if (response.getObjContents().get(0) != null) {
							if (response.getObjContents().get(1) != null) {
								Integer seqNum = (Integer)response.getObjContents().get(1);
								if (seqNum == sequenceNumber + 1) {
									sequenceNumber += 2;
									//retrieve the group server's public value
									//PublicKey groupServerPK = (PublicKey)response.getObjContents().get(0);
									// generate the shared secret key
									//SecretKey secretKey = DiffieHellman.generateSecretKey(groupServerPK, twoFactorkeyAgreement);
									//byte[] bSecretKey = secretKey.getEncoded();
									//Base32 codec = new Base32();
									//byte[] bEncodedKey = codec.encode(bSecretKey);
									return (String)response.getObjContents().get(0);
								}
							}
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

	/**
	* Disconnect from the connected server.
	*/
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


/*-------------------------------TEST METHODS---------------------------------*/

	public UserToken wrongSequenceToken(String username, PublicKey serverKey) {
		try {
			UserToken token = null;
			Envelope message = null, response = null;
			Envelope superE = null, superResponse = null;	 	
			//Tell the server to return a token.
			message = new Envelope("GET");
			message.addObject(username); //Add user name string
			message.addObject(serverKey);
			message.addObject(sequenceNumber-1); //Add sequence number
			System.out.println("Client Sequence Number = " + sequenceNumber);
			System.out.println("Sequence Number Sent = " + (sequenceNumber + 1));
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
						System.out.println("Server Number Received = " + seqNum);
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
	

/*-------------------------OLD PASSWORD CODE----------------------------------*/
	/*
	// Old suthentication protocol	
	public int authenticateGroupServer(String username, String password) throws Exception {
		sessionKey = establishSessionKey();
		if (sessionKey == null) {
			// Unable to make the sessionKey();
			return -1;
		}
		return login(username, password);
	}

	// Old login protocol unneded with new RSA code
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

	// Old password update function, unneeded now that we only use RSA
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
	
	// Old DiffieHellman. Can get Man in the Middled
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
