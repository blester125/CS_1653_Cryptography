import java.security.Key;
import java.util.ArrayList;


public class GroupMetadata implements java.io.Serializable {
	    private static final long serialVersionUID = -8960097447400932609L;
	    
	    private String groupname;
	    private Key currentKey;
	    private int currentKeyVer;
	    private ArrayList<Key> oldKeys;
	    
	    public GroupMetadata(String groupname, Key currentKey, int currentKeyVer, ArrayList<Key> oldKeys) {
	    	this.groupname = groupname;
	    	this.currentKey = currentKey;
	    	this.currentKeyVer = currentKeyVer;
	    	this.oldKeys = oldKeys;
		}
	    
	    public String getGroupname() {
	    	return this.groupname;
	    }
	    
	    public Key getCurrentKey() {
	    	return currentKey;
	    }

	    public int getCurrentKeyVer() {
	    	return currentKeyVer;
	    }
	    
	    public ArrayList<Key> getOldKeys() {
	    	return oldKeys;
	    }
  }
