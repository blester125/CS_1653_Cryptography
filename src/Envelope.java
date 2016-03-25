import java.util.ArrayList;

import javax.crypto.KeyAgreement;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import java.security.Key;

public class Envelope implements java.io.Serializable {
	
	/**
	 * 
	 */
	private static final long serialVersionUID = -7726335089122193103L;
	private String msg;
	private ArrayList<Object> objContents = new ArrayList<Object>();
	
	public Envelope(String text)
	{
		msg = text;
	}
	
	public String getMessage()
	{
		return msg;
	}
	
	public ArrayList<Object> getObjContents()
	{
		return objContents;
	}
	
	public void addObject(Object object)
	{
		objContents.add(object);
	}

	@Override
	public String toString() {
		return "Envelope [msg=" + msg + ", objContents=" + objContents + "]";
	}

	/*
		Big Error with Hashes in general. most hashes use some sort of toString()
		in the hash making process which causes a problem. for example the tostrings
		of the same envelop on different computers is different
		ie:
			Envelope [msg=SUCCESS, objContents=[[B@79c04b2a, 95]]
		vs.
			Envelope [msg=SUCCESS, objContents=[[B@24ebd76a, 95]]

		I beleive that there have been a few times that we are hasing the address
		of objects rather than the objects themselves. A lost of things have this 
		probelm notable sealedeObjects that we can't make HMAC's out of because they
		cannot be converted to byte arrays
	*/ 
	public static Envelope buildSuper(Envelope env, SecretKey key) {
		IvParameterSpec ivSpec = CipherBox.generateRandomIV();
		Envelope superEnv = new Envelope("SUPER");
		SealedObject sealedEnv = CipherBox.encrypt(env, key, ivSpec);
		byte[] HMAC = Hasher.generateHMAC(key, sealedEnv);
		//byte[] HMAC = Hasher.generateHMAC(key, env);
		//System.out.println(new String(HMAC));
		superEnv.addObject(sealedEnv);
		superEnv.addObject(ivSpec.getIV());
		superEnv.addObject(HMAC);
		return superEnv;
	}

	public static Envelope extractInner(Envelope env, SecretKey key) {
		if (env != null) {
			if (env.getObjContents().size() == 3) {
				if (env.getObjContents().get(0) != null) {
					if (env.getObjContents().get(1) != null) {
						if (env.getObjContents().get(2) != null) {
							SealedObject sealedEnv = (SealedObject)env.getObjContents().get(0);
							IvParameterSpec ivSpec = new IvParameterSpec((byte[])env.getObjContents().get(1));
							byte[] HMAC = (byte[])env.getObjContents().get(2);
							if (Hasher.verifiyHMAC(HMAC, key, sealedEnv)) {
								return (Envelope)CipherBox.decrypt(sealedEnv, key, ivSpec);
							}
							//Envelope contents = (Envelope)CipherBox.decrypt(sealedEnv, key, ivSpec);
							//System.out.println(contents);
							//if (Hasher.verifiyHMAC(HMAC, key, contents)) {
							//	return contents;
							//}
						}
					}
				}
			}
		}
		return null;
	}
}
