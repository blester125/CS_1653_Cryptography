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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.SecretKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

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
				FileOutputStream keyOut = new FileOutputStream(publicKeyPath);
				keyOut.write(x590keyspec.getEncoded());
				keyOut.close();

				PKCS8EncodedKeySpec pkcs8keyspec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
				keyOut = new FileOutputStream(privateKeyPath);
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

	// Loads public RSA key then takes the system input private key
	public static KeyPair loadRSA(String publicKeyPath, PrivateKey inputPrivate) {
		//Attempt to load RSA key pair from file
		try{
			KeyPair rsaPair;
			File fsPublicKey = new File(publicKeyPath);
			FileInputStream keyIn = new FileInputStream(publicKeyPath);
			byte[] encPublicKey = new byte[(int) fsPublicKey.length()];
			keyIn.read(encPublicKey);
			keyIn.close();

			KeyFactory kf = KeyFactory.getInstance("RSA", "BC");
			X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encPublicKey);
			PublicKey publicKey = kf.generatePublic(publicKeySpec);

			rsaPair = new KeyPair(publicKey, inputPrivate);

			System.out.println("Found public RSA key and parsed private RSA key. Loaded successfully!");
			return rsaPair;
		}
		catch (FileNotFoundException e) {
			try {
				System.out.println("Did not find public and/or private RSA keys.");
			
				return null;
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

	// Loads server RSA keys and decrypts private key from disk
	public static KeyPair loadRSA(String publicKeyPath, String privateKeyPath, SecretKey convertPrivate) {
		//Attempt to load RSA key pair from file
		ObjectInputStream privateFileStream;
		try{
			KeyPair rsaPair;
			File fsPublicKey = new File(publicKeyPath);
			FileInputStream keyIn = new FileInputStream(publicKeyPath);
			byte[] encPublicKey = new byte[(int) fsPublicKey.length()];
			keyIn.read(encPublicKey);
			keyIn.close();

			File fsPrivateKey = new File(privateKeyPath);
			keyIn = new FileInputStream(privateKeyPath);
			privateFileStream = new ObjectInputStream(keyIn);
			Envelope tempEnv = (Envelope)privateFileStream.readObject();
			PrivateKey privateKey = (PrivateKey)Envelope.extractInner(tempEnv, convertPrivate).getObjContents().get(0);
			keyIn.close();

			KeyFactory kf = KeyFactory.getInstance("RSA", "BC");
			X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encPublicKey);
			PublicKey publicKey = kf.generatePublic(publicKeySpec);

			rsaPair = new KeyPair(publicKey, privateKey);

			System.out.println("Found RSA key pair. Decrypted and loaded successfully!");
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
				FileOutputStream keyOut = new FileOutputStream(publicKeyPath);
				keyOut.write(x590keyspec.getEncoded());
				keyOut.close();

				Envelope privateKeyEnv = new Envelope("ServerPrivateKey");
				privateKeyEnv.addObject(privateKey);
				Envelope superPrivateKeyEnv = Envelope.buildSuper(privateKeyEnv, convertPrivate);

				ObjectOutputStream outStream = new ObjectOutputStream(new FileOutputStream(privateKeyPath));
				outStream.writeObject(superPrivateKeyEnv);

				System.out.println("New RSA key pair generated and stored!");
				System.out.println("Server private key encrypted!");
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

	public static String generateFingerprints(PublicKey key) {
		if (key == null) {
			return "null";
		}
		return javax.xml.bind.DatatypeConverter.printHexBinary(Hasher.hash(key));
	}

	public static void main(String args[]){

		Security.addProvider(new BouncyCastleProvider());

		//generate server and admin keys
		KeyPair adminPair = loadRSA("adminpublic.key", "adminprivate.key");
		
		//generate sample user keys (carl)
		loadRSA("alicepublic.key", "aliceprivate.key");
		loadRSA("bobpublic.key", "bobprivate.key");
		loadRSA("carolpublic.key", "carolprivate.key");
		loadRSA("davepublic.key", "daveprivate.key");
		loadRSA("evepublic.key", "eveprivate.key");
		loadRSA("fredpublic.key", "fredprivate.key");
		loadRSA("gregpublic.key", "gregprivate.key");
		loadRSA("harrypublic.key", "harryprivate.key");
		loadRSA("igorpublic.key", "igorprivate.key");
		loadRSA("jillpublic.key", "jillprivate.key");
		loadRSA("trentpublic.key", "trentprivate.key");


		System.out.println("Starter/Admin (adminprivate.key) private key: \n" + KeyBox.getKeyAsString(adminPair.getPrivate()));
	}
}
