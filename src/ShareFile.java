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
public class ShareFile implements java.io.Serializable, Comparable<ShareFile> {

	private static final long serialVersionUID = -6699986336399821598L;
	private String group;
	private String path;
	private String owner;
	private int keyIndex;
	private int keyVersion;
	private byte[] iv;
	private long length;
	
	public ShareFile(
						String _owner, 
						String _group, 
						String _path, 
						int _keyIndex,
						int _keyVersion,
						byte[] _iv,
						long _length) {
		group = _group;
		owner = _owner;
		path = _path;
		keyIndex = _keyIndex;
		keyVersion = _keyVersion;
		iv = _iv;
		length = _length;
	}
	
	public String getPath()
	{
		return path;
	}
	
	public String getOwner()
	{
		return owner;
	}
	
	public String getGroup() {
		return group;
	}

	public int getKeyIndex() {
		return keyIndex;
	}

	public int getKeyVersion() {
		return keyVersion;
	}
	
	public byte[] getIv() {
		return iv;
	}
	
	public long getLength() {
		return length;
	}
	
	public int compareTo(ShareFile rhs) {
		if (path.compareTo(rhs.getPath())==0)return 0;
		else if (path.compareTo(rhs.getPath())<0) return -1;
		else return 1;
	}
	
	
}	
