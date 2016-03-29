import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.KeyAgreement;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class RSA {

	static final int RSA_BIT_KEYSIZE = 2048;

	// Loads my RSA keys
	public static KeyPair loadRSA(String publicKeyPath, String privateKeyPath) {
		//Attempt to load RSA key pair from file
		try{
			KeyPair rsaPair;
			File fsPublicKey = new File(publicKeyPath);
			FileInputStream keyIn = new FileInputStream(publicKeyPath);
			byte[] encPublicKey = new byte[(int) fsPublicKey.length()];
			keyIn.read(encPublicKey);
			keyIn.close();

			File fsPrivateKey = new File(privateKeyPath);
			keyIn = new FileInputStream(privateKeyPath);
			byte[] encPrivateKey = new byte[(int) fsPrivateKey.length()];
			keyIn.read(encPrivateKey);
			keyIn.close();

			KeyFactory kf = KeyFactory.getInstance("RSA", "BC");
			X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encPublicKey);
			PublicKey publicKey = kf.generatePublic(publicKeySpec);

			PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encPrivateKey);
			PrivateKey privateKey = kf.generatePrivate(privateKeySpec);

			rsaPair = new KeyPair(publicKey, privateKey);

			System.out.println("Found RSA key pair. Loaded successfully!");
			return rsaPair;
		}
		catch (FileNotFoundException e) {
			try {
				System.out.println("Did not find public and/or private RSA keys. Generating new key pair....");
			
				//Generate RSA key pair with KeyPairGenerator, 1024 bits
				KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
				keyGen.initialize(RSA_BIT_KEYSIZE);
				KeyPair rsaPair = keyGen.generateKeyPair();
				PrivateKey privateKey = rsaPair.getPrivate();
				PublicKey publicKey = rsaPair.getPublic();

				//Store both keys to file
				X509EncodedKeySpec x590keyspec = new X509EncodedKeySpec(publicKey.getEncoded());
				FileOutputStream keyOut = new FileOutputStream("userpublic.key");
				keyOut.write(x590keyspec.getEncoded());
				keyOut.close();

				PKCS8EncodedKeySpec pkcs8keyspec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
				keyOut = new FileOutputStream("userprivate.key");
				keyOut.write(pkcs8keyspec.getEncoded());
				keyOut.close();

				System.out.println("New RSA key pair generated and stored!");
				return rsaPair;
			}
			catch (Exception f){
				System.out.println("Exception thrown in create new RSA pair.");
				return null;
			}

		}
		catch (IOException e) {
			System.out.println("Could not read or write from/to key files!");
			return null;
		}
		catch (NoSuchAlgorithmException e){
			System.out.println("Algorithm does not exist!");
			return null;
		}
		catch (InvalidKeySpecException e){
			System.out.println("Invalid key specification!");
			return null;
		}
		catch (Exception e){
			System.out.println("unspecified exception thrown");
			return null;
		}
	}

	// Loads only a public key from file (instead of generating a KeyPair object)
	public static PublicKey loadPublic(String publicKeyPath){

		try {
			//Get only public key from file
			File fsPublicKey = new File(publicKeyPath);
			FileInputStream keyIn = new FileInputStream(publicKeyPath);
			byte[] encPublicKey = new byte[(int) fsPublicKey.length()];
			keyIn.read(encPublicKey);
			keyIn.close();

			KeyFactory kf = KeyFactory.getInstance("RSA", "BC");
			X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encPublicKey);
			PublicKey publicKey = kf.generatePublic(publicKeySpec);

			System.out.println("Found RSA public key. Loaded successfully!");
			return publicKey;
		} catch (Exception e) {
			System.out.println("Error loading RSA public key from file path: " + publicKeyPath);
			return null;
		}

	}

	// Load the groupserver public key
	public static PublicKey loadServerKey(String path) {
		try {
			File fsPublicKey = new File(path);
			FileInputStream keyIn = new FileInputStream(path);
			byte[] encPublicKey = new byte[(int) fsPublicKey.length()];
			keyIn.read(encPublicKey);
			keyIn.close();
			KeyFactory kf = KeyFactory.getInstance("RSA", "BC");
			X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encPublicKey);
			PublicKey publicKey = kf.generatePublic(publicKeySpec);
			System.out.println("Loaded in the server public key");
			return publicKey;
		} catch (Exception e) {
			System.out.println("You need the servers Public Key.");
			return null;
		}
	}
}
