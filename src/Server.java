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

import java.security.SecureRandom;
import java.util.Date;

public abstract class Server {
	
	protected int port;
	public String name;
	abstract void start();
	
	public Server(int _SERVER_PORT, String _serverName) {
		port = _SERVER_PORT;
		name = _serverName; 
	}
	
		
	public int getPort() {
		return port;
	}
	
	public String getName() {
		return name;
	}

	public boolean isFresh(Date timestamp) {
		Date now = new Date();
		if ((now.getTime() - timestamp.getTime()) < 30000L) {
			return true;
		} 
		return false;
	}
}
