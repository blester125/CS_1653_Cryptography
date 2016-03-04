/* FileClient provides all the client functionality regarding the file server */

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import java.security.SecureRandom;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.SealedObject;

public class FileClient extends Client implements FileClientInterface {
	private SecretKey secretKey;
	
	public FileClient() {

	}

	public Envelope buildSuper(Envelope env){

		IvParameterSpec ivspec = CipherBox.generateRandomIV();			
		Envelope superEnv = new Envelope("SUPER");
		superEnv.addObject(CipherBox.encrypt(env, secretKey, ivspec));
		superEnv.addObject(ivspec);

		return superEnv;
	}

	public Envelope extractInner(Envelope superInputEnv){

		SealedObject innerEnv = (SealedObject)superInputEnv.getObjContents().get(0);
		IvParameterSpec decIVSpec = new IvParameterSpec((byte[])superInputEnv.getObjContents().get(1));
		Envelope env = (Envelope)CipherBox.decrypt(innerEnv, secretKey, decIVSpec);

		return env;
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
			Envelope superEnv = buildSuper(env);
			output.writeObject(superEnv);

			//receive, extract, and decrypt inner envelope
			env = extractInner((Envelope)input.readObject());
		   
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
						Envelope superEnv = buildSuper(env);
					    output.writeObject(superEnv); 
					
					   //receive, extract, and decrypt inner envelope
						env = extractInner((Envelope)input.readObject());
					    
						while (env.getMessage().compareTo("CHUNK")==0) { 
								fos.write((byte[])env.getObjContents().get(0), 0, (Integer)env.getObjContents().get(1));
								System.out.printf(".");

								env = new Envelope("DOWNLOADF"); //Success
								output.writeObject(buildSuper(env));

								env = extractInner((Envelope)input.readObject());									
						}										
						fos.close();
						
					    if(env.getMessage().compareTo("EOF")==0) {
					    	 fos.close();
								System.out.printf("\nTransfer successful file %s\n", sourceFile);
								env = new Envelope("OK"); //Success
								output.writeObject(buildSuper(env));
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
			 output.writeObject(buildSuper(message)); 
			 
			 e = extractInner((Envelope)input.readObject());
			 
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
			 output.writeObject(buildSuper(message)); 
			 
			 e = extractInner((Envelope)input.readObject());
			 
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
			 output.writeObject(buildSuper(message));
			
			 
			 FileInputStream fis = new FileInputStream(sourceFile);
			 
			 env = extractInner((Envelope)input.readObject());
			 
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
					
					output.writeObject(buildSuper(message));
					
					
					env = extractInner((Envelope)input.readObject());
					
										
			 }
			 while (fis.available()>0);		 
					 
			 //If server indicates success, return the member list
			 if(env.getMessage().compareTo("READY")==0)
			 { 
				
				message = new Envelope("EOF");
				output.writeObject(buildSuper(message));
				
				env = extractInner((Envelope)input.readObject());
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
	  * Establish a shared session key and send + verify a challenge,
	  * fully authenticating the server.
	  * @return	true on success, false on failure
	  */
	public boolean authenticateServer(){

		return false;
	}

	/**
	  * establishes a shared session key by generating a shared symmetric key between
	  * the client and the server 
	  * @return	SecretKey
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
				//retrieve the group server's public value
				PublicKey fileServerPK = (PublicKey)response.getObjContents().get(0);

				// generate the shared secret key
				secretKey = DiffieHellman.generateSecretKey(fileServerPK, keyAgreement);
				System.out.println(secretKey.getEncoded());
	
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

