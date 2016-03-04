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
	
	public void insertServerInfo(ServerInfo serverInfo, PublicKey pk) {
		serverReg.put(serverInfo, pk);
	}
	
	public PublicKey getServerPublicKey(ServerInfo serverInfo) {
		return serverReg.get(serverInfo);
	}
}
