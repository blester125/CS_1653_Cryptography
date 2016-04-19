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

import java.net.Socket;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import javax.crypto.SealedObject;

public abstract class Client {

	/* 
	 * Socket and input/output streams
	 */
	protected Socket sock;
	protected ObjectOutputStream output;
	protected ObjectInputStream input;

	public boolean connect(final String server, final int port) {
		System.out.println("attempting to connect");

		try {
			// Connect to the server
			sock = new Socket(server, port);
			System.out.println("Connected to " + server + " on port " + port);  
			// Setup I/O streams with the server
			output = new ObjectOutputStream(sock.getOutputStream());
			input = new ObjectInputStream(sock.getInputStream());
			return true;
		}
		catch(Exception e) {
			System.err.println(e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}

	}

	public boolean isConnected() {
		if (sock == null || !sock.isConnected() || sock.isClosed()) {
			return false;
		}
		else {
			return true;
		}
	}

	public void disconnect() {
		if (isConnected()) {
			try
			{
				Envelope message = new Envelope("DISCONNECT");
				System.out.println(message);
				output.writeObject(message);
				sock.close(); //close the socket
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
			}
		}
	}

	public boolean solvePuzzle() {
		int number = 0;
		SealedObject encryptedAnswer = null;
		byte[] answer = null;
		byte[] hash = null;
		try {
			Envelope message = new Envelope("PUZZLE");
			output.writeObject(message);
			// recive puzzle and solve
			Envelope response = (Envelope)input.readObject();
			if (response != null) {
				if (response.getMessage().equals("PUZZLEOK")) {
					if (response.getObjContents().size() == 3) {
						if (response.getObjContents().get(0) != null) {
							if (response.getObjContents().get(1) != null) {
								if (response.getObjContents().get(2) != null) {
									number = (Integer)response.getObjContents().get(0);
									hash = (byte[])response.getObjContents().get(1);
									encryptedAnswer = (SealedObject)response.getObjContents().get(1);
								}
							}
						}
					}
				}
			}
			answer = Hasher.bruteForce(number, hash);
			message = new Envelope("ANSWER");
			message.addObject(answer);
			message.addObject(encryptedAnswer);
			output.writeObject(message);
			response = (Envelope)input.readObject();
			if (response != null) {
				if (response.getMessage().equals("OK")) {
					return true;
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return false;
	}
}
