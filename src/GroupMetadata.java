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

import java.util.ArrayList;

import javax.crypto.SecretKey;


public class GroupMetadata implements java.io.Serializable {
	    private static final long serialVersionUID = -8960097447400932609L;
	    
	    private String groupname;
	    private SecretKey currentKey;
	    private int currentKeyVer;
	    private int currentKeyIndex;
	    private ArrayList<SecretKey> oldKeys;
	    
	    /**
	     * 
	     * @param groupname
	     * @param currentKey
	     * @param currentRootKey
	     * @param currentKeyVer
	     * @param keyList
	     */
	    public GroupMetadata(String groupname, SecretKey currentKey, int currentKeyIndex, 
	    		int currentKeyVer, ArrayList<SecretKey> oldKeys) {
	    	this.groupname = groupname;
	    	this.currentKey = currentKey;
	    	this.currentKeyIndex = currentKeyIndex;
	    	this.currentKeyVer = currentKeyVer;
	    	this.oldKeys = oldKeys;
		}
	    
	    public String getGroupname() {
	    	return this.groupname;
	    }
	    
	    public SecretKey getCurrentKey() {
	    	return currentKey;
	    }
	    
	    public SecretKey getCurrentConfKey() {
	    	return KeyBox.generateConfidentialityKey(currentKey);
	    }
	    
	    public SecretKey getCurrentIntegKey() {
	    	return KeyBox.generateIntegrityKey(currentKey);
	    }
	    
	    public int getCurrentKeyIndex() {
	    	return currentKeyIndex;
	    }

	    public int getCurrentKeyVer() {
	    	return currentKeyVer;
	    }
	    
	    
	    public ArrayList<SecretKey> getOldKeys() {
	    	return oldKeys;
	    }
	    
	    /**
	     * calculates the correct key from the given meta-data
	     * @param _index
	     * @param _version
	     * @return	the key
	     */
	    public SecretKey calculateKey(int _index, int _version) {
	    	// check if using newest root key
	    	if(_index >= oldKeys.size()) {
	    		return KeyBox.evolveKey(currentKey, _version - currentKeyVer);
	    	}
	    	else {
	    		return KeyBox.evolveKey(oldKeys.get(_index), _version);
	    	}
	    }
  }
