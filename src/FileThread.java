/* File worker thread handles the business of uploading, downloading, and removing files for clients with valid tokens */

import java.lang.Thread;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

public class FileThread extends Thread
{
	private final Socket socket;

	public FileThread(Socket _socket)
	{
		socket = _socket;
	}

	public void run()
	{
		boolean proceed = true;
		try
		{
			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
			final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
			final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
			Envelope response;

			do
			{
				Envelope e = (Envelope)input.readObject();
				System.out.println("Request received: " + e.getMessage());

				// Handler to list files that this user is allowed to see
				if(e.getMessage().equals("LFILES"))
				{
				    //Do error handling
				    if(e.getObjContents().size() < 1) {
				    	response = new Envelope("FAIL-BADCONTENTS");
				    }
				    else {
				    	if(e.getObjContents().get(0) == null) {
				    		response = new Envelope("FAIL-BADTOKEN");
				    	}
				    	else {

				    		//Prepare output list of file names and retrieve the token from the envelope
						    ArrayList<String> filteredFiles = new ArrayList<String>();
						    UserToken tok = (UserToken)e.getObjContents().get(0);

						    //Get all files from the FileServer
						    ArrayList<ShareFile> all = FileServer.fileList.getFiles();

						    //Go through all files in the server, filter for only those in the right group
						    for(ShareFile f : all){

						    	if(tok.getGroups().contains(f.getGroup()))
						    		filteredFiles.add(f.getPath());
						    }

						    //form response, write it
						    response = new Envelope("OK");
						    response.addObject(filteredFiles);
						    output.writeObject(response);
						    System.out.println("SENT from LFILES: " + response);
				    	}
				    }   	
				}
				if(e.getMessage().equals("LFILESG")) //List only files in specified group
				{
				    //Do error handling
				    if(e.getObjContents().size() < 1) {
				    	response = new Envelope("FAIL-BADCONTENTS");
				    }
				    else {
				    	if(e.getObjContents().get(0) == null) {
				    		response = new Envelope("FAIL-BADTOKEN");
				    	}
				    	else {

				    		//Prepare output list of file names and retrieve the token from the envelope
						    ArrayList<String> finalFiles = new ArrayList<String>();
						    ArrayList<ShareFile> filteredFiles = new ArrayList<ShareFile>();
						    String groupName = (String)e.getObjContents().get(0);
						    UserToken tok = (UserToken)e.getObjContents().get(1);


						    //Get all files from the FileServer
						    ArrayList<ShareFile> all = FileServer.fileList.getFiles();

						    //Go through all files in the server, filter for only those in the right group
						    for(ShareFile f : all){

						    	if(tok.getGroups().contains(f.getGroup()))
						    		filteredFiles.add(f);
						    }

						    //Go through all filtered files, only return one group's
						    for(ShareFile f : filteredFiles){

						    	if(f.getGroup().equals(groupName))
						    		finalFiles.add(f.getPath());
						    }



						    //form response, write it
						    response = new Envelope("OK");
						    response.addObject(finalFiles);
						    output.writeObject(response);
						    System.out.println("SENT from LFILESG: " + response);
				    	}
				    }   	
				}
				if(e.getMessage().equals("UPLOADF"))
				{

					if(e.getObjContents().size() < 3)
					{
						response = new Envelope("FAIL-BADCONTENTS");
					}
					else
					{
						if(e.getObjContents().get(0) == null) {
							response = new Envelope("FAIL-BADPATH");
						}
						if(e.getObjContents().get(1) == null) {
							response = new Envelope("FAIL-BADGROUP");
						}
						if(e.getObjContents().get(2) == null) {
							response = new Envelope("FAIL-BADTOKEN");
						}
						else {
							String remotePath = (String)e.getObjContents().get(0);
							String group = (String)e.getObjContents().get(1);
							UserToken yourToken = (UserToken)e.getObjContents().get(2); //Extract token

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
								File file = new File("shared_files/"+remotePath.replace('/', '_'));
								file.createNewFile();
								FileOutputStream fos = new FileOutputStream(file);
								System.out.printf("Successfully created file %s\n", remotePath.replace('/', '_'));

								response = new Envelope("READY"); //Success
								output.writeObject(response);
								System.out.println("SENT from UPLOADF - READY: " + response);

								e = (Envelope)input.readObject();
								while (e.getMessage().compareTo("CHUNK")==0) {
									fos.write((byte[])e.getObjContents().get(0), 0, (Integer)e.getObjContents().get(1));
									response = new Envelope("READY"); //Success
									output.writeObject(response);
									System.out.println("SENT from UPLOADF - READYCHUNK: " + response);
									e = (Envelope)input.readObject();
								}

								if(e.getMessage().compareTo("EOF")==0) {
									System.out.printf("Transfer successful file %s\n", remotePath);
									FileServer.fileList.addFile(yourToken.getSubject(), group, remotePath);
									response = new Envelope("OK"); //Success
								}
								else {
									System.out.printf("Error reading file %s from client\n", remotePath);
									response = new Envelope("ERROR-TRANSFER"); //Success
								}
								fos.close();
							}
						}
					}

					output.writeObject(response);
					System.out.println("SENT from UPLOADF: " + response);
				}
				else if (e.getMessage().compareTo("DOWNLOADF")==0) {

					String remotePath = (String)e.getObjContents().get(0);
					Token t = (Token)e.getObjContents().get(1);
					ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
					if (sf == null) {
						System.out.printf("Error: File %s doesn't exist\n", remotePath);
						e = new Envelope("ERROR_FILEMISSING");
						output.writeObject(e);
						System.out.println("SENT from DOWNLOADF - ERROR_FILEMISSING: " + e);

					}
					else if (!t.getGroups().contains(sf.getGroup())){
						System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
						e = new Envelope("ERROR_PERMISSION");
						output.writeObject(e);
						System.out.println("SENT from DOWNLOADF - ERROR_PERMISSION: " + e);
					}
					else {

						try
						{
							File f = new File("shared_files/_"+remotePath.replace('/', '_'));
						if (!f.exists()) {
							System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
							e = new Envelope("ERROR_NOTONDISK");
							output.writeObject(e);
							System.out.println("SENT from DOWNLOADF - ERROR_NOTONDISK: " + e);

						}
						else {
							FileInputStream fis = new FileInputStream(f);

							do {
								byte[] buf = new byte[4096];
								if (e.getMessage().compareTo("DOWNLOADF")!=0) {
									System.out.printf("Server error: %s\n", e.getMessage());
									break;
								}
								e = new Envelope("CHUNK");
								int n = fis.read(buf); //can throw an IOException
								if (n > 0) {
									System.out.printf(".");
								} else if (n < 0) {
									System.out.println("Read error");

								}


								e.addObject(buf);
								e.addObject(new Integer(n));

								output.writeObject(e);
								System.out.println("SENT from DOWNLOADF: " + e);

								e = (Envelope)input.readObject();


							}
							while (fis.available()>0);

							//If server indicates success, return the member list
							if(e.getMessage().compareTo("DOWNLOADF")==0)
							{

								e = new Envelope("EOF");
								output.writeObject(e);
								System.out.println("SENT from DOWNLOADF - EOF: " + e);

								e = (Envelope)input.readObject();
								if(e.getMessage().compareTo("OK")==0) {
									System.out.printf("File data download successful\n");
								}
								else {

									System.out.printf("Upload failed: %s\n", e.getMessage());

								}

							}
							else {

								System.out.printf("Upload failed: %s\n", e.getMessage());

							}
						}
						}
						catch(Exception e1)
						{
							System.err.println("Error: " + e.getMessage());
							e1.printStackTrace(System.err);

						}
					}
				}
				else if (e.getMessage().compareTo("DELETEF")==0) {

					String remotePath = (String)e.getObjContents().get(0);
					Token t = (Token)e.getObjContents().get(1);
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
								e = new Envelope("OK");
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
					output.writeObject(e);
					System.out.println("SENT from DELETEF: " + e);

				}
				else if(e.getMessage().equals("DISCONNECT"))
				{
					socket.close();
					proceed = false;
				}
			} while(proceed);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}

}
