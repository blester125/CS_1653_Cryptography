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
import java.security.Security;
import java.util.ArrayList;

import javax.crypto.KeyGenerator;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Envelope implements java.io.Serializable {
	
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

	public static Envelope buildSuper(Envelope env, SecretKey key) {
		IvParameterSpec ivSpec = CipherBox.generateRandomIV();
		Envelope superEnv = new Envelope("SUPER");
		SealedObject sealedEnv = CipherBox.encrypt(env, 
							KeyBox.generateConfidentialityKey(key), ivSpec);
		byte[] HMAC = generateIntegrityCheck(
							KeyBox.generateIntegrityKey(key), sealedEnv, ivSpec);
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
							if (checkIntegrity(KeyBox.generateIntegrityKey(key), sealedEnv, ivSpec, HMAC)) {
								return (Envelope)CipherBox.decrypt(sealedEnv, KeyBox.generateConfidentialityKey(key), ivSpec);
							}
						}
					}
				}
			}
		}
		return null;
	}

	private static byte[] generateIntegrityCheck(
								Key k, 
								SealedObject so, 
								IvParameterSpec iv) {
		byte[] so_ba = Hasher.convertToByteArray(so);
		byte[] iv_ba = iv.getIV();
		byte[] concat = Hasher.concatenateArrays(so_ba, iv_ba);
		return Hasher.generateHMAC(k, concat);
	}

	private static boolean checkIntegrity(
								Key k, 
								SealedObject so, 
								IvParameterSpec iv, 
								byte[] recvHMAC) {
		byte[] madeHMAC = generateIntegrityCheck(k, so, iv);
		System.out.println("\n-------------------------------------");
		System.out.println("Integrity Check on the SUPER envelope");
		System.out.println(new String(recvHMAC));
		System.out.println(new String(madeHMAC));
		System.out.println("-------------------------------------");
		return Hasher.verifyHMAC(recvHMAC, madeHMAC);
	}

	public static void main(String args[]) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		Envelope env = new Envelope("Test");
		String testString = "TEST STRING";
		env.addObject(testString);

		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(128);
		SecretKey key = keyGen.generateKey();

		IvParameterSpec ivSpec = CipherBox.generateRandomIV();
		Envelope superEnv = new Envelope("SUPER");
		SealedObject sealedEnv = CipherBox.encrypt(env, key, ivSpec);
		SealedObject sealTwo = CipherBox.encrypt(env, key, ivSpec);

		byte[] barr = Hasher.convertToByteArray(sealedEnv);
		byte[] barr2 = Hasher.convertToByteArray(sealTwo);

		System.out.println(new String(barr));
		System.out.println("---------------------------");
		System.out.println(new String(barr2));
		System.out.println("---------------------------");
		System.out.println(new String(barr).equals(new String(barr2)));

	}
}
