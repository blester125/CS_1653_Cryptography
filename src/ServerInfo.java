public class ServerInfo {
	private String hostname;
	private String port;
	
	public ServerInfo(String hostname, String port) {
		this.hostname = hostname;
		this.port = port;
	}
	
	public String getHostname() {
		return this.hostname;
	}
	public String getPort() {
		return this.getPort();
	}
	@Override
	public int hashCode() {
		return (this.hostname + this.port).hashCode();
	}
}