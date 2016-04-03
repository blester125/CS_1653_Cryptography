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
import java.security.PublicKey;
import java.util.Hashtable;
import java.io.Serializable;


public class ServerRegistry implements Serializable {
	private static final long serialVersionUID = 5463198767498412185L;	
	private Hashtable<ServerInfo, PublicKey> serverReg;
										  
	
	public ServerRegistry() {
		this.serverReg = new Hashtable<ServerInfo, PublicKey>();
	}
	
	public ServerRegistry(Hashtable<ServerInfo, PublicKey> serverReg) {
		this.serverReg = serverReg;
	}
	
	/**
	 * Add the <serverInfo, publicKey> pair into the table
	 * @param serverInfo: The information about the socket connected to
	 * @param pk: The public key
	 */
	public void insertServerInfo(ServerInfo serverInfo, PublicKey pk) {
		serverReg.put(serverInfo, pk);
	}
	
	/**
	 * Get the public key stored with the serverInfo
	 * @param serverInfo: The server info to look up
	 * @return PublicKey on success, null on failure
	 */
	public PublicKey getServerPublicKey(ServerInfo serverInfo) {
		return serverReg.get(serverInfo);
	}
}
