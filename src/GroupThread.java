/* This thread does all the work. It communicates with the client through Envelopes.
 * 
 */
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.KeyAgreement;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class GroupThread extends Thread 
{
	private final Socket socket;
	private GroupServer my_gs;
	private boolean isSecureConnection;
	private KeyPair rsaKeyPair;
	private SecretKey sessionKey;
	private String username = null;

	public GroupThread(Socket _socket, GroupServer _gs)
	{
		socket = _socket;
		my_gs = _gs;
		isSecureConnection = false;
		sessionKey = null;
		rsaKeyPair = my_gs.keyPair;
	}

	public Envelope buildSuper(Envelope env){

		IvParameterSpec ivspec = CipherBox.generateRandomIV();			
		Envelope superEnv = new Envelope("SUPER");
		superEnv.addObject(CipherBox.encrypt(env, sessionKey, ivspec));
		superEnv.addObject(ivspec.getIV());

		return superEnv;
	}

	public Envelope extractInner(Envelope superInputEnv){

		SealedObject innerEnv = (SealedObject)superInputEnv.getObjContents().get(0);
		IvParameterSpec decIVSpec = new IvParameterSpec((byte[])superInputEnv.getObjContents().get(1));
		Envelope env = (Envelope)CipherBox.decrypt(innerEnv, sessionKey, decIVSpec);

		return env;
	}
	
	public void run()
	{
		boolean proceed = true;
		try
		{
			//Announces connection and opens object streams
			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
			final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
			final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
			
			do
			{
				Envelope message = null; // = (Envelope)input.readObject();
				Envelope response;
				Envelope innerResponse;
				if(!isSecureConnection) {
					message = (Envelope)input.readObject();
				}
				// decrypt envelopes after establishing a secure connection with
				// a shared symmetric secret key
				else {
					try {
						Envelope superE = (Envelope)input.readObject();
						message = extractInner(superE);
					} catch(Exception e) {
						e.printStackTrace();
						response = new Envelope("FAIL");
						response.addObject(response);
						output.writeObject(response);
					}
				}
				// null message check
				if(message == null) {
					response = new Envelope("FAIL");
					response.addObject(response);
					output.writeObject(response);
				}
				
				System.out.println("Request received: " + message.getMessage());
				
				// Client wishes to establish a shared symmetric secret key
				if(message.getMessage().equals("SESSIONKEY")) {
					// Retrieve Client's public key
					PublicKey clientPK = (PublicKey)message.getObjContents().get(0);
					KeyPair keypair = null;
					KeyAgreement keyAgreement = null;
					// generate secret key and send back public key
					try {
						keypair = DiffieHellman.genKeyPair();
						keyAgreement = DiffieHellman.genKeyAgreement(keypair);
						sessionKey = DiffieHellman.generateSecretKey(clientPK, keyAgreement);
						response = new Envelope("OK");
						response.addObject(keypair.getPublic());
						output.writeObject(response);
						isSecureConnection = true;
					} catch(Exception e) {
						e.printStackTrace();
						response = new Envelope("FAIL");
						response.addObject(response);
						output.writeObject(response);
					}
				}
				else if (message.getMessage().equals("RSALOGIN")) {
					String user = (String)message.getObjContents().get(0);
					SealedObject sealedHash = (SealedObject)message.getObjContents().get(1);
					PublicKey userPublicKey = getUserPublicKey(user);
					if (userPublicKey != null) {
						byte[] recvHash = (byte[])CipherBox.decrypt(sealedHash, userPublicKey);
						PublicKey DHuserKey = (PublicKey)message.getObjContents().get(2);
						if (MessageDigest.isEqual(recvHash, Hasher.hash(DHuserKey))) {
							
							KeyPair keyPair = null;
							KeyAgreement keyAgreement = null;
							// generate secret key and send back public key
							try {
								keyPair = DiffieHellman.genKeyPair();
								keyAgreement = DiffieHellman.genKeyAgreement(keyPair);
								sessionKey = DiffieHellman.generateSecretKey(DHuserKey, keyAgreement);
								response = new Envelope("RSALOGINOK");
								byte[] hashedPublicKey = Hasher.hash(keyPair.getPublic());
								SealedObject sealedKey;
								sealedKey = CipherBox.encrypt(hashedPublicKey, my_gs.keyPair.getPrivate());
								response.addObject(sealedKey);
								response.addObject(keyPair.getPublic());
								output.writeObject(response);
								Envelope check = (Envelope)input.readObject();
								Envelope innerCheck = extractInner(check);
								if (innerCheck.getMessage().equals("SUCCESS")) {
									isSecureConnection = true;
									username = user;
								}
							} catch(Exception e) {
								e.printStackTrace();
							}
						}
						else {
							response = new Envelope("FAIL");
							output.writeObject(response);
						}
					}
					else {
						response = new Envelope("FAIL");
						output.writeObject(response);
					}
				}
				else if(message.getMessage().equals("LOGIN") 
							&& isSecureConnection) {

					if (message.getObjContents().size() < 2)
					{
				 		innerResponse = new Envelope("FAIL");
				 	}
				 	else
				 	{
				 		innerResponse = new Envelope("FAIL");
				 		if (message.getObjContents().get(0) != null)
				 		{
				 			if (message.getObjContents().get(1) != null)
							{
								innerResponse = new Envelope("FAIL");
								String user = (String)message.getObjContents().get(0);
								String password = (String)message.getObjContents().get(1);
								if (checkUser(user, password)) {
									username = user;
									if (checkFlag(username)) {
										innerResponse = new Envelope("CHANGEPASSWORD");
									}
									else {
										innerResponse = new Envelope("OK");
									}
								}
								else {
									innerResponse = new Envelope("FAIL");
								}
 							}
				 		}
					}
					response = buildSuper(innerResponse);
					output.writeObject(response);
				}
				else if (message.getMessage().equals("CHANGEPASSWORD") 
							&& isSecureConnection 
							&& username != null) {
					if (message.getObjContents().size() < 1) {
						innerResponse = new Envelope("FAIL");
					}
					else {
						innerResponse = new Envelope("FAIL");
						if (message.getObjContents().get(0) != null) {
							// Force "LOGIN" to have been run before "CHANGEPASSWORD"
							if (username != null) {
								String password = (String)message.getObjContents().get(0);
								if (setPassword(username, password)) {
									innerResponse = new Envelope("OK");
								}
							}
						}
					}
					response = buildSuper(innerResponse);
					output.writeObject(response);
				}
				else if (message.getMessage().equals("RSAKEY")
							&& isSecureConnection) {
					if (message.getObjContents().size() < 1) {
						innerResponse = new Envelope("FAIL");
					}
					else {
						innerResponse = new Envelope("FAIL");
						if (message.getObjContents().get(0) != null) {
							if (username != null) {
								PublicKey userKey = (PublicKey)message.getObjContents().get(0);
								if (setRSAKey(username, userKey)) {
									innerResponse = new Envelope("OK");
								}
							}
						}
					}
					response = buildSuper(innerResponse);
					output.writeObject(response);
				}
				else if (message.getMessage().equals("GET") 
							&& isSecureConnection
							&& username != null) {//Client wants a token
					String user = (String)message.getObjContents().get(0); //Get the username
					if (user == null) {
						innerResponse = new Envelope("FAIL");
					}
					else {
						innerResponse = new Envelope("FAIL");
						UserToken yourToken = createToken(username); //Create a token
						//Respond to the client. On error, the client will receive a null token
						
						// Sign token
						if (yourToken.signToken(my_gs.keyPair.getPrivate())) {
							innerResponse = new Envelope("OK");
							innerResponse.addObject(yourToken);
							ArrayList<Group> = my_gs.
						}
					}
					System.out.println("SENT from GET: " + innerResponse);
					response = buildSuper(innerResponse);
					output.writeObject(response);
				}
				else if (message.getMessage().equals("CUSER") 
							&& isSecureConnection
							&& username != null) {
					if (message.getObjContents().size() < 3) {
						innerResponse = new Envelope("FAIL");
					}
					else {
						innerResponse = new Envelope("FAIL");
						if(message.getObjContents().get(0) != null) {
							if(message.getObjContents().get(1) != null) {
								if (message.getObjContents().get(2) != null) {
									String username = (String)message.getObjContents().get(0); //Extract the username
									String password = (String)message.getObjContents().get(1);
									UserToken yourToken = (UserToken)message.getObjContents().get(2); //Extract the token	
									if (createUser(username, password, yourToken)) {
										innerResponse = new Envelope("OK"); //Success
									}
								}
							}
						}
					}
					System.out.println("SENT from CUSER: " + innerResponse);
					response = buildSuper(innerResponse);
					output.writeObject(response);
				}
				else if(message.getMessage().equals("DUSER") 
						&& isSecureConnection
						&& username != null) //Client wants to delete a user
				{
					if (message.getObjContents().size() < 2) {
						innerResponse = new Envelope("FAIL");
					}
					else {
						innerResponse = new Envelope("FAIL");
						
						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								String username = (String)message.getObjContents().get(0); //Extract the username
								UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token
								
								if(deleteUser(username, yourToken))
								{
									innerResponse = new Envelope("OK"); //Success
								}
							}
						}
					}
					System.out.println("SENT from DUSER: " + innerResponse);
					response = buildSuper(innerResponse);
					output.writeObject(response);
				}
				else if(message.getMessage().equals("CGROUP") 
						&& isSecureConnection
						&& username != null) //Client wants to create a group
				{	
					if (message.getObjContents().size() < 2) {
						innerResponse = new Envelope("FAIL");
					}
					else {
						innerResponse = new Envelope("FAIL");
						
						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								String groupname = (String)message.getObjContents().get(0); //Extract the groupname
								UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token
								
								if(createGroup(groupname, yourToken))
								{
									innerResponse = new Envelope("OK"); //Success
								}
							}
						}
					}
					
					System.out.println("SENT from CGROUP: " + innerResponse);
					response = buildSuper(innerResponse);
					output.writeObject(response);
				}
				else if(message.getMessage().equals("DGROUP") 
						&& isSecureConnection
						&& username != null) //Client wants to delete a group
				{
					if (message.getObjContents().size() < 2) {
						innerResponse = new Envelope("FAIL");
					}
					else
					{
						innerResponse = new Envelope("FAIL");
						
						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								String groupname = (String)message.getObjContents().get(0); //Extract the groupname
								UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token
								
								if(deleteGroup(groupname, yourToken))
								{
									innerResponse = new Envelope("OK"); //Success
								}
							}
						}
					}
					System.out.println("SENT from DGROUP: " + innerResponse);
					response = buildSuper(innerResponse);
					output.writeObject(response);
				}
				else if(message.getMessage().equals("LMEMBERS") 
						&& isSecureConnection
						&& username != null) //Client wants a list of members in a group
				{
					// If there isn't enough information in the envelope
					if (message.getObjContents().size() < 2) 
					{
						innerResponse = new Envelope("FAIL");
					}
					else 
					{
						innerResponse = new Envelope("FAIL");
						// If there is no groupName
						if (message.getObjContents().get(0) != null)
						{
							//If there is no Token
							if (message.getObjContents().get(1) != null)
							{
								// Extract groupName
								String groupName = (String)message.getObjContents().get(0);
								// Extract Token 
								UserToken yourToken = (UserToken)message.getObjContents().get(1);
								// Get the memeber list for this group
								List<String> members = listMembers(groupName, yourToken);
								// If a list was returned
								if (members != null) 
								{
									// Craft the envelope
									innerResponse = new Envelope("OK");
									innerResponse.addObject(members);
									
								}
							}
						}
					}
					System.out.println("SENT from LMEMBERS: " + innerResponse);
					output.flush();
					output.reset();
					response = buildSuper(innerResponse);
					output.writeObject(response);
				}
				else if(message.getMessage().equals("AUSERTOGROUP") 
						&& isSecureConnection
						&& username != null) //Client wants to add user to a group
				{
					// Is there a userName, groupName, and Token in the Envelope
					if (message.getObjContents().size() < 3)
					{
						innerResponse = new Envelope("FAIL");
					}
					else
					{
						innerResponse = new Envelope("FAIL");
						if (message.getObjContents().get(0) != null)
						{
							if (message.getObjContents().get(1) != null)
							{
								if (message.getObjContents().get(2) != null)
								{
									String userName = (String)message.getObjContents().get(0);
									String groupName = (String)message.getObjContents().get(1);
									UserToken yourToken = (UserToken)message.getObjContents().get(2);
									if (addUserToGroup(userName, groupName, yourToken))
									{
										innerResponse = new Envelope("OK");
									}
								}
							}
						}
					}
					System.out.println("SENT from AUSERTOGROUP: " + innerResponse);
					response = buildSuper(innerResponse);
					output.writeObject(response);
				}
				else if(message.getMessage().equals("RUSERFROMGROUP") 
						&& isSecureConnection
						&& username != null) //Client wants to remove user from a group
				{
					// Is there a userName, groupName, and Token in the Envelope
					if (message.getObjContents().size() < 3)
					{
						innerResponse = new Envelope("FAIL");
					}
					else
					{
						innerResponse = new Envelope("FAIL");
						if (message.getObjContents().get(0) != null)
						{
							if (message.getObjContents().get(1) != null)
							{
								if (message.getObjContents().get(2) != null)
								{
									String userName = (String)message.getObjContents().get(0);
									String groupName = (String)message.getObjContents().get(1);
									UserToken yourToken = (UserToken)message.getObjContents().get(2);
									if (deleteUserFromGroup(userName, groupName, yourToken))
									{
										innerResponse = new Envelope("OK");
									}
								}
							}
						}
					}
					System.out.println("SENT from RUSERFROMGROUP: " + innerResponse);
					response = buildSuper(innerResponse);
					output.writeObject(response);
				}
				else if(message.getMessage().equals("DISCONNECT") 
						&& isSecureConnection
						&& username != null) //Client wants to disconnect
				{
					isSecureConnection = false;
					username = null;
					sessionKey = null;
					socket.close(); //Close the socket
					proceed = false; //End this communication loop
				}
				else
				{
					innerResponse = new Envelope("FAIL"); //Server does not understand client request
					System.out.println("SENT from INVALID MESSAGE: " + innerResponse);
					response = buildSuper(innerResponse);
					output.writeObject(response);
				}
			}while(proceed);	
		}
		catch(Exception e)
		{
			isSecureConnection = false;
			username = null;
			sessionKey = null;
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
	
	//Method to create tokens
	private UserToken createToken(String username) 
	{

		//Check that user exists
		if(my_gs.userList.checkUser(username))
		{
			//Add the timestamp and signage
			//Issue a new token with server's name, user's name, and user's groups
			UserToken yourToken = new Token(my_gs.name, username, my_gs.userList.getUserGroups(username));
			System.out.println(yourToken);
			return yourToken;
		}
		else
		{
			return null;
		}
	}
	
	
	//Method to create a user
	private boolean createUser(String username, 
						String password, 
						UserToken yourToken) {
		String requester = yourToken.getSubject();
		
		//Check if requester exists
		if (my_gs.userList.checkUser(requester)) {
			//Get the user's groups
			ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
			//requester needs to be an administrator
			if (temp.contains("ADMIN")) {
				//Does user already exist?
				if (my_gs.userList.checkUser(username)) {
					return false; //User already exists
				}
				else {
					my_gs.userList.addUser(username);
					BigInteger salt = Passwords.generateSalt();
					my_gs.userList.setSalt(username, salt);
					byte[] hashword = Passwords.generatePasswordHash(
													password, 
													salt); 
					my_gs.userList.setPassword(username, hashword);
					return true;
				}
			}
			else {
				return false; //requester not an administrator
			}
		}
		else {
			return false; //requester does not exist
		}
	}
	
	//Method to delete a user
	private boolean deleteUser(String username, UserToken yourToken)
	{
		String requester = yourToken.getSubject();

		//can't delete yourself
		if(requester.equals(username))
			return false;
		
		//Does requester exist?
		if(my_gs.userList.checkUser(requester))
		{
			ArrayList<String> temp = my_gs.userList.getUserGroups(requester);

			//requester needs to be an administer
			if(temp.contains("ADMIN"))
			{
				//Does user exist?
				if(my_gs.userList.checkUser(username))
				{
					//User needs deleted from the groups they belong
					ArrayList<String> deleteFromGroups = new ArrayList<String>();
					
					//This will produce a hard copy of the list of groups this user belongs
					for(int index = 0; index < my_gs.userList.getUserGroups(username).size(); index++)
					{
						deleteFromGroups.add(my_gs.userList.getUserGroups(username).get(index));
					}
					
					//Delete the user from the groups
					//If user is the owner, removeMember will automatically delete group!
					for(int index = 0; index < deleteFromGroups.size(); index++)
					{
						System.out.println("index: " + index + ", group: " + deleteFromGroups.get(index));
						my_gs.groupList.removeMember(deleteFromGroups.get(index), username);
					}
					
					//If groups are owned, they must be deleted
					ArrayList<String> deleteOwnedGroup = new ArrayList<String>();
					
					//Make a hard copy of the user's ownership list
					for(int index = 0; index < my_gs.userList.getUserOwnership(username).size(); index++)
					{
						deleteOwnedGroup.add(my_gs.userList.getUserOwnership(username).get(index));
					}
					
					//Delete owned groups
					for(int index = 0; index < deleteOwnedGroup.size(); index++)
					{
						//Use the delete group method. Token must be created for this action
						deleteGroup(deleteOwnedGroup.get(index), new Token(my_gs.name, username, deleteOwnedGroup));
					}
					
					//Delete the user from the user list
					my_gs.userList.deleteUser(username);
					
					return true;	
				}
				else
				{
					return false; //User does not exist
					
				}
			}
			else
			{
				return false; //requester is not an administer
			}
		}
		else
		{
			return false; //requester does not exist
		}
	}
	
	/**
	 * creates the group with the specified name, assigning the user of the corresponding
	 * token to be its owner
	 * @param groupName	name of the group
	 * @param token	token of user creating group (group owner)
	 * @return	true on success, false on failure
	 */
	private boolean createGroup(String groupName, UserToken token) {
		String requester = token.getSubject();
		
		// Check if group does not exist
		// this assumes all group names must be unique, regardless of owner
		if(!my_gs.groupList.checkGroup(groupName))
		{
			
			if(my_gs.userList.checkUser(requester)){
				
				my_gs.groupList.createGroup(groupName, requester);
				my_gs.groupList.addMember(groupName, requester);
				my_gs.userList.addGroup(requester, groupName);
				my_gs.userList.addOwnership(requester, groupName);
				return true;
			}
			return false;
		}
		else
		{
			return false; //group exists
		}
	}
	
	/**
	 * Deletes the specified group, as requested by the given user's token
	 * @param groupName	group to be deleted
	 * @param token	token of user requesting group deletion
	 * @return	true on success, false on failure
	 */
	private boolean deleteGroup(String groupName, UserToken token) {
		String requester = token.getSubject();
		
		if(groupName.equals("ADMIN"))
			return false;

		// check if group exists
		if(my_gs.groupList.checkGroup(groupName))
		{
			// check if requester is the group's owner
			if(my_gs.groupList.getGroupOwner(groupName).equals(requester)) {
				// delete group from users
				for(String user : my_gs.groupList.getGroupUsers(groupName)) {
					my_gs.userList.removeGroup(user, groupName);
				}
				// delete the group
				my_gs.groupList.deleteGroup(groupName);
				return true;
			}
		}
		
		return false;
	}
	
	/**
	 * Lists the members in the specified group
	 * @param groupName group to list the members of
	 * @param token token of the user requesting the list
	 * @return List of strings on success, null on failure
	 */
	private List<String> listMembers(String groupName, UserToken token)
	{
		//Get the requester
		String requester = token.getSubject();
		// Does the requester exist?
		if (my_gs.userList.checkUser(requester))
		{
			// Get the groups the requester belongs to
			ArrayList<String> groups = my_gs.userList.getUserGroups(requester);

			// is the user authorized to be in this group?
			// check requester is the owner of the group
			if (groups.contains(groupName) && my_gs.groupList.getGroupOwner(groupName).equals(requester))
			{
				// get the members of this group
				return my_gs.groupList.getGroupUsers(groupName);
			}
			// The user is not authorized to see this group
			else 
			{
				return null;
			}
		}
		// The requester doesn't exist
		else
		{
			return null;
		}
	}

	/**
	 * Add specified user to specified group
	 * @param userName user to be added to the group
	 * @param groupName group for the user to be added to
	 * @param token token of user requesting the addition
	 * @return true in success, false on failure
	 */
	private boolean addUserToGroup(String userName, String groupName, UserToken token)
	{
		String requester = token.getSubject();
		if (my_gs.userList.checkUser(requester))
		{
			ArrayList<String> owns = my_gs.userList.getUserOwnership(requester);
			if (owns.contains(groupName))
			{
				if (my_gs.userList.checkUser(userName))
				{
					ArrayList<String> users_in_group = my_gs.groupList.getGroupUsers(groupName);
					if (!users_in_group.contains(userName))
					{
						//Add user to group
						my_gs.groupList.addMember(groupName, userName);
						// add group to user
						my_gs.userList.addGroup(userName, groupName);
						return true;
					}
					else
					{ // User is already in the group
						return false;
					}
				}
				else
				{ // user to be added doesn't exist
					return false;
				}
			}
			else
			{ // requester doesn't own the group
				return false;
			}
		}
		else
		{ // requester doesn't exist
			return false;
		}
	}

	/**
	 * Delete specified user to specified group
	 * @param userName user to be deleted from the group
	 * @param groupName group for the user to be removed from
	 * @param token token of user requesting the deletion
	 * @return true in success, false on failure
	 */
	private boolean deleteUserFromGroup(String userName, String groupName, UserToken token)
	{
		String requester = token.getSubject();
		if (my_gs.userList.checkUser(requester))
		{
			ArrayList<String> owns = my_gs.userList.getUserOwnership(requester);
			if (owns.contains(groupName))
			{
				if (my_gs.userList.checkUser(userName))
				{
					ArrayList<String> users_in_group = my_gs.groupList.getGroupUsers(groupName);
					if (users_in_group.contains(userName))
					{
						// remove user from group
						my_gs.groupList.removeMember(groupName, userName);
						// remove group from user
						my_gs.userList.removeGroup(userName, groupName);
						return true;
					}
					else
					{ // User is not in the group
						return false;
					}
				}
				else
				{ // user to be added doesn't exist
					return false;
				}
			}
			else
			{ // requester doesn't own the group
				return false;
			}
		}
		else
		{ // requester doesn't exist
			return false;
		}
	}

	private boolean checkUser(String user, String pwd) {
		if (my_gs.userList.checkUser(user) == false) {
			return false;
		}
		BigInteger salt = my_gs.userList.getSalt(user);
		byte[] password = Passwords.generatePasswordHash(pwd, salt);
		return my_gs.userList.checkPassword(user, password);
	}

	private boolean checkFlag(String user) {
		return my_gs.userList.getNewPassword(user);
	}

	private boolean setPassword(String user, String password) {
		BigInteger salt = Passwords.generateSalt();
		my_gs.userList.setSalt(user, salt);
		byte[] hashword = Passwords.generatePasswordHash(password, salt);
		my_gs.userList.setPassword(user, hashword);
		my_gs.userList.setNewPassword(user, false);
		return true;
	}

	private boolean setRSAKey(String user, PublicKey key) {
		my_gs.userList.setPublicKey(user, key);
		return true;
	}

	private PublicKey getUserPublicKey(String user) {
		return my_gs.userList.getPublicKey(user);
	}
}
