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

import java.security.Key;
import java.security.PrivateKey;
import java.security.Security;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.crypto.SealedObject;


public class Token implements UserToken {
	private static final long serialVersionUID = 897646161548165146L;
	private String issuer;
	private String subject;
	private ArrayList<String> groups;
	private Date timestamp;
	private SealedObject signedHash;
	private final long networkTolerance = 10000L;
	private Key publicKey;
	
	public static final String sentinal = "#";
	
	Token(String issuer, String subject, ArrayList<String> in_groups) {
		this.issuer = issuer;
		this.subject = subject;
		this.groups = new ArrayList<String>(in_groups.size());
		for(String group : in_groups)
			this.groups.add(group);
		this.timestamp = new Date();
	}
	
	Token(String issuer, String subject, ArrayList<String> in_groups, Key publicKey) {
		this.issuer = issuer;
		this.subject = subject;
		this.groups = new ArrayList<String>(in_groups.size());
		for(String group : in_groups)
			this.groups.add(group);
		this.timestamp = new Date();
		this.publicKey = publicKey;
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
		try {
			byte[] hashToken = Hasher.hash(this);
			signedHash = CipherBox.encrypt(hashToken, privateKey);
			return true;
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
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
	
	public SealedObject getSignedHash() {
		return this.signedHash;
	}
	
	public Key getPublicKey() {
		return this.publicKey;
	}
	
	@Override
	public boolean isFresh() {
		Date currentTime = new Date();
		if((currentTime.getTime() - this.timestamp.getTime()) < networkTolerance) {
			return true;
		}
		return false;
	};

	@Override
	public String toString() {
		String token = this.timestamp + sentinal + this.issuer + sentinal + this.subject;
		for(String group : this.groups) {
			token += sentinal + group;
		}
		token += sentinal + this.publicKey;
		return token;
	}

	public static void main(String[] args) {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		UserToken t = new Token("issue","subject",new ArrayList<String>());
		System.out.println(new String(Hasher.hash(t)));
		t.signToken(null);
	}
	
}
