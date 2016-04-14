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

import java.lang.reflect.Field;
import java.security.Security;
import java.security.PublicKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.KeyAgreement;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;

import java.io.*;
import org.apache.commons.codec.binary.Base32;

public class Dos {

	 static GroupClient groupC;
	 static FileClient fileC;
	 static KeyPair keyPair;

	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		try {
	        Field field = Class.forName("javax.crypto.JceSecurity").getDeclaredField("isRestricted");
	        field.setAccessible(true);
	        field.set(null, java.lang.Boolean.FALSE);
	    } catch (Exception ex) {
	    	ex.printStackTrace();
	    }
		
		keyPair = RSA.loadRSA("dospublic.key", "dosprivate.key");
		PublicKey serverPublicKey = RSA.loadServerKey("groupserverpublic.key");
		while (true) {
			groupC = new GroupClient();
			fileC = new FileClient();
			groupC.connect("localhost", 8080);
			groupC.authenticateGroupServerRSA("test", "adminpublic.key", "adminprivate.key");
			UserToken t = groupC.getToken("test", serverPublicKey);
		}
	}

	public static void login() throws Exception {
		KeyPair dhKeyPair = null;
		KeyAgreement keyAgreement = null;
		dhKeyPair = DiffieHellman.genKeyPair();
		keyAgreement = DiffieHellman.genKeyAgreement(dhKeyPair);
		byte[] hashedPublicKey = Hasher.hash(dhKeyPair.getPublic());
		// System.out.println(new String(hashedPublicKey));
		// System.out.println(keyPair);
		// System.out.println(keyPair.getPrivate());
		SealedObject sealedKey = CipherBox.encrypt(hashedPublicKey, keyPair.getPrivate());
		Envelope message = new Envelope("RSALOGIN");
		message.addObject("test");
		message.addObject(sealedKey);
		message.addObject(dhKeyPair.getPublic());
		groupC.output.writeObject(message);
	}
}