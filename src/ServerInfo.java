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

import java.io.Serializable;
import java.net.Socket;


public class ServerInfo implements Serializable {
	private String hostname;
	private String port;
	private static final long serialVersionUID = 2674987946519874951L;

	
	public ServerInfo(String hostname, String port) {
		this.hostname = hostname;
		this.port = port;
	}
	
	public ServerInfo(Socket sock) {
		this.hostname = sock.getInetAddress().getHostName();
		this.port = Integer.toString(sock.getPort());
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

	@Override
	public boolean equals(Object other) {
		ServerInfo temp = (ServerInfo)other;
		if(this.hostname.equals(temp.hostname) && this.port.equals(temp.port))
			return true;
		else
			return false;
	}
}