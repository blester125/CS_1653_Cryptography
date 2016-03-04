import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;


public class Token implements UserToken {
	private static final long serialVersionUID = 897646161548165146L;
	private String issuer;
	private String subject;
	private ArrayList<String> groups;
	private Date timestamp;
	private byte[] signedHash;
	
	public static final String sentinal = "#";
	
	Token(String issuer, String subject, ArrayList<String> in_groups) {
		this.issuer = issuer;
		this.subject = subject;
		this.groups = new ArrayList<String>(in_groups.size());
		for(String group : in_groups)
			this.groups.add(group);
		this.timestamp = new Date();
	}
	
	Token(String issuer, String subject, ArrayList<String> in_groups, Date timestamp) {
		this.issuer = issuer;
		this.subject = subject;
		this.groups = new ArrayList<String>(in_groups.size());
		for(String group : in_groups)
			this.groups.add(group);
		this.timestamp = timestamp;
	}
	
	/**
	 * sets the signed hash value of the token
	 * @param privateKey	private key used for signing
	 * @return	true on success, false on failure
	 */
	public boolean signToken(PrivateKey privateKey) {
		Signature signature = null;
		try {
			signature = Signature.getInstance("SHA256", "BC");
		} catch (NoSuchAlgorithmException e3) {
			e3.printStackTrace();
		} catch (NoSuchProviderException e3) {
			e3.printStackTrace();
			return false;
		}
	    try {
			signature.initSign(privateKey, new SecureRandom());
		} catch (InvalidKeyException e2) {
			e2.printStackTrace();
			return false;
		}
	    byte[] message = this.toString().getBytes();
	    try {
			signature.update(message);
		} catch (SignatureException e1) {
			e1.printStackTrace();
			return false;
		}
	    try {
			this.signedHash = signature.sign();
		} catch (SignatureException e) {
			e.printStackTrace();
			return false;
		}
	    return true;
	}
	
	@Override
	public String getIssuer() {
		return this.issuer;
	}

	@Override
	public String getSubject() {
		return this.subject;
	}

	@Override
	public List<String> getGroups() {
		return this.groups;
	}
	
	public byte[] getSignedHash() {
		return this.signedHash;
	}

	@Override
	public String toString() {
		String token = this.timestamp + sentinal + this.issuer + sentinal + this.subject;
		for(String group : this.groups) {
			token += sentinal + group;
		}
		return token;
	}
	
}
