/* This thread does all the work. It communicates with the client through Envelopes.
 * 
 */
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;

public class GroupThread extends Thread 
{
	private final Socket socket;
	private GroupServer my_gs;
	private SecretKey secretKey;
	private boolean isSecureConnection;
	
	public GroupThread(Socket _socket, GroupServer _gs)
	{
		socket = _socket;
		my_gs = _gs;
		isSecureConnection = false;
	}
	
	public void run()
	{
		boolean proceed = true;
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		try
		{
			//Announces connection and opens object streams
			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
			final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
			final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
			
			do
			{
				Envelope message = (Envelope)input.readObject();
				System.out.println("Request received: " + message.getMessage());
				Envelope response;
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
						secretKey = DiffieHellman.generateSecretKey(clientPK, keyAgreement);
						System.out.println(secretKey.getEncoded());
						response = new Envelope("OK");
						response.addObject(keypair.getPublic());
						output.writeObject(response);
					} catch(Exception e) {
						e.printStackTrace();
						response = new Envelope("FAIL");
						response.addObject(response);
						output.writeObject(response);
					}
				}
				else if(message.getMessage().equals("GET"))//Client wants a token
				{
					String username = (String)message.getObjContents().get(0); //Get the username
					if(username == null)
					{
						response = new Envelope("FAIL");
						response.addObject(null);
						System.out.println("SENT from GET: " + response);
						output.writeObject(response);
					}
					else
					{
						UserToken yourToken = createToken(username); //Create a token
						
						//Respond to the client. On error, the client will receive a null token
						response = new Envelope("OK");
						response.addObject(yourToken);
						/*System.out.println("SENT from GET: " + response);
						Cipher cipher = Cipher.getInstance("AES");
						SecretKeySpec secreteKeySpec = new SecretKeySpec(new byte[] {(byte)0x01, (byte)0x02, (byte)0x01, (byte)0x02,(byte)0x01, (byte)0x02, (byte)0x01, (byte)0x02,(byte)0x01, (byte)0x02, (byte)0x01, (byte)0x02,(byte)0x01, (byte)0x02, (byte)0x01, (byte)0x02}, "AES");
						cipher.init(Cipher.ENCRYPT_MODE, secreteKeySpec);
						SealedObject responseEncrypted = CipherBox.encrypt(response, cipher);
						output.writeObject(responseEncrypted);*/
						output.writeObject(response);
						
					}
				}
				else if(message.getMessage().equals("CUSER")) //Client wants to create a user
				{
					if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");
						
						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								String username = (String)message.getObjContents().get(0); //Extract the username
								UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token
								
								if(createUser(username, yourToken))
								{
									response = new Envelope("OK"); //Success
								}
							}
						}
					}
					System.out.println("SENT from CUSER: " + response);
					output.writeObject(response);
				}
				else if(message.getMessage().equals("DUSER")) //Client wants to delete a user
				{
					
					if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");
						
						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								String username = (String)message.getObjContents().get(0); //Extract the username
								UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token
								
								if(deleteUser(username, yourToken))
								{
									response = new Envelope("OK"); //Success
								}
							}
						}
					}
					System.out.println("SENT from DUSER: " + response);
					output.writeObject(response);
				}
				else if(message.getMessage().equals("CGROUP")) //Client wants to create a group
				{	
					//System.out.println("rcvd: " + message + " " + message.getObjContents().size());
					if(message.getObjContents().size() < 1) //size is always two+? not sure why this was set to < 2
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");
						
						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								String groupname = (String)message.getObjContents().get(0); //Extract the groupname
								UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token
								
								if(createGroup(groupname, yourToken))
								{
									response = new Envelope("OK"); //Success
								}
							}
						}
					}
					
					System.out.println("SENT from CGROUP: " + response);
					output.writeObject(response);

				}
				else if(message.getMessage().equals("DGROUP")) //Client wants to delete a group
				{
					if(message.getObjContents().size() < 1)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");
						
						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								String groupname = (String)message.getObjContents().get(0); //Extract the groupname
								UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token
								
								if(deleteGroup(groupname, yourToken))
								{
									response = new Envelope("OK"); //Success
								}
							}
						}
					}
					System.out.println("SENT from DGROUP: " + response);
					output.writeObject(response);
				}
				else if(message.getMessage().equals("LMEMBERS")) //Client wants a list of members in a group
				{
					// If there isn't enough information in the envelope
					if (message.getObjContents().size() < 2) 
					{
						response = new Envelope("FAIL");
					}
					else 
					{
						response = new Envelope("FAIL");
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

								System.out.println(groupName + " , " + yourToken + " , " + members);
								// If a list was returned
								if (members != null) 
								{
									// Craft the envelope
									response = new Envelope("OK");
									response.addObject(members);
									
								}
							}
						}
					}
					System.out.println("SENT from LMEMBERS: " + response);
					output.flush();
					output.reset();
					output.writeObject(response);
				}
				else if(message.getMessage().equals("AUSERTOGROUP")) //Client wants to add user to a group
				{
					// Is there a userName, groupName, and Token in the Envelope
					if (message.getObjContents().size() < 3)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");
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
										response = new Envelope("OK");
									}
								}
							}
						}
					}
					System.out.println("SENT from AUSERTOGROUP: " + response);
					output.writeObject(response);
				}
				else if(message.getMessage().equals("RUSERFROMGROUP")) //Client wants to remove user from a group
				{
					// Is there a userName, groupName, and Token in the Envelope
					if (message.getObjContents().size() < 3)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");
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
										response = new Envelope("OK");
									}
								}
							}
						}
					}
					System.out.println("SENT from RUSERFROMGROUP: " + response);
					output.writeObject(response);
				}
				else if(message.getMessage().equals("DISCONNECT")) //Client wants to disconnect
				{
					socket.close(); //Close the socket
					proceed = false; //End this communication loop
				}
				else
				{
					response = new Envelope("FAIL"); //Server does not understand client request
					System.out.println("SENT from DISCONNECT: " + response);
					output.writeObject(response);
				}
			}while(proceed);	
		}
		catch(Exception e)
		{
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
	private boolean createUser(String username, UserToken yourToken)
	{
		String requester = yourToken.getSubject();
		
		//Check if requester exists
		if(my_gs.userList.checkUser(requester))
		{
			//Get the user's groups
			ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
			//requester needs to be an administrator
			if(temp.contains("ADMIN"))
			{
				//Does user already exist?
				if(my_gs.userList.checkUser(username))
				{
					return false; //User already exists
				}
				else
				{
					my_gs.userList.addUser(username);
					return true;
				}
			}
			else
			{
				return false; //requester not an administrator
			}
		}
		else
		{
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
}
