/* Implements the GroupClient Interface */

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.io.ObjectInputStream;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.security.SecureRandom;
import javax.crypto.spec.IvParameterSpec;

public class GroupClient extends Client implements GroupClientInterface {
	private Cipher AESCipherEncrypt;
	private Cipher AESCipherDecrypt;
	private SecretKey sessionKey;
	
	public GroupClient() {
		try {
			AESCipherEncrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		}
		try {
			AESCipherDecrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		}
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

	public int authenticateGroupServer(String username, String password) throws Exception {
		Envelope message, response = null;
		sessionKey = establishSessionKey();
		if (sessionKey == null) {
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
			return -1;
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
 
	public UserToken getToken(String username)
	{
		try
		{
			UserToken token = null;
			Envelope message = null, response = null;
				 	
			//Tell the server to return a token.
			message = new Envelope("GET");
			message.addObject(username); //Add user name string
			//output.writeObject(CipherBox.encrypt(message, AESCipherEncrypt));
		
			//Get the response from the server
			/*SealedObject sa = (SealedObject)input.readObject();
			System.out.println(sa.toString());
			Cipher cipher = Cipher.getInstance("AES");
			SecretKeySpec secreteKeySpec = new SecretKeySpec(new byte[] {(byte)0x01, (byte)0x02, (byte)0x01, (byte)0x02,(byte)0x01, (byte)0x02, (byte)0x01, (byte)0x02,(byte)0x01, (byte)0x02, (byte)0x01, (byte)0x02,(byte)0x01, (byte)0x02, (byte)0x01, (byte)0x02}, "AES");
			cipher.init(Cipher.DECRYPT_MODE, secreteKeySpec);
			response = (Envelope) CipherBox.decrypt(sa, cipher);
			System.out.println(response.getMessage());*/
			//response = (Envelope)CipherBox.decrypt((SealedObject)input.readObject(), AESCipherDecrypt);
			
			
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
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return null;
		}
		
	 }
	 
	 public boolean createUser(String username, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to create a user
				message = new Envelope("CUSER");
				message.addObject(username); //Add user name string
				message.addObject(token); //Add the requester's token
				output.writeObject(message);
			
				response = (Envelope)input.readObject();
				
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}
				
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }
	 
	 public boolean deleteUser(String username, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
			 
				//Tell the server to delete a user
				message = new Envelope("DUSER");
				message.addObject(username); //Add user name
				message.addObject(token);  //Add requester's token
				output.writeObject(message);
			
				response = (Envelope)input.readObject();
				
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}
				
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }
	 
	 public boolean createGroup(String groupname, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to create a group
				message = new Envelope("CGROUP");
				message.addObject(groupname); //Add the group name string
				message.addObject(token); //Add the requester's token
				output.writeObject(message); 
				//System.out.println("Sent: " + message);
			
				response = (Envelope)input.readObject();
				
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}
				
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }
	 
	 public boolean deleteGroup(String groupname, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to delete a group
				message = new Envelope("DGROUP");
				message.addObject(groupname); //Add group name string
				message.addObject(token); //Add requester's token
				output.writeObject(message); 
			
				response = (Envelope)input.readObject();
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}
				
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }
	 
	 @SuppressWarnings("unchecked")
	public List<String> listMembers(String group, UserToken token)
	 {
		 try
		 {

		 	 output.flush();
		 	 output.reset();

			 Envelope message = null, response = null;
			 //Tell the server to return the member list
			 message = new Envelope("LMEMBERS");
			 message.addObject(group); //Add group name string
			 message.addObject(token); //Add requester's token
			 output.writeObject(message); 
			 
			 response = (Envelope)input.readObject();
			 
			 //If server indicates success, return the member list
			 if(response.getMessage().equals("OK"))
			 { 

			 	System.out.println( response);

				return (List<String>)response.getObjContents().get(0); //This cast creates compiler warnings. Sorry.
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
	 
	 public boolean addUserToGroup(String username, String groupname, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to add a user to the group
				message = new Envelope("AUSERTOGROUP");
				message.addObject(username); //Add user name string
				message.addObject(groupname); //Add group name string
				message.addObject(token); //Add requester's token
				output.writeObject(message); 
			
				response = (Envelope)input.readObject();
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}
				
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }
	 
	 public boolean deleteUserFromGroup(String username, String groupname, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to remove a user from the group
				message = new Envelope("RUSERFROMGROUP");
				message.addObject(username); //Add user name string
				message.addObject(groupname); //Add group name string
				message.addObject(token); //Add requester's token
				output.writeObject(message);
			
				response = (Envelope)input.readObject();
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}
				
				return false;
			}
			catch(Exception e)
			{
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
			if(response.getMessage().equals("OK"))
			{
				//retrieve the group server's public value
				PublicKey groupServerPK = (PublicKey)response.getObjContents().get(0);
				// generate the shared secret key
				SecretKey secretKey = DiffieHellman.generateSecretKey(groupServerPK, keyAgreement);
				System.out.println(new String(secretKey.getEncoded()));
	
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
}
