import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;
import java.security.interfaces.*;

import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.sun.crypto.provider.SunJCE;


public class DiffieHellman {

	// The 2048 bit Diffie-Hellman modulus value
	private static final String hex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";
    private static final byte modulusBytes[] = new BigInteger(hex,16).toByteArray();
    
    // g and q, respectively
	private static final BigInteger base = BigInteger.valueOf(2);
	private static final BigInteger modulus = new BigInteger(1, modulusBytes);

	//Add the bouncy castle API as the provider for the JCE
	//Security.addProvider(new BouncyCastleProvider());

	public static void main(String args[]) throws Exception {

		//Test functionality (ensure secret keys match)
		Security.addProvider(new BouncyCastleProvider());

		KeyPair aliceKeyPair = genKeyPair();
		KeyPair bobKeyPair = genKeyPair();

		KeyAgreement aliceKeyAgree = genKeyAgreement(aliceKeyPair);
		KeyAgreement bobKeyAgree = genKeyAgreement(bobKeyPair);

		SecretKey aliceSecretKey = generateSecretKey(bobKeyPair.getPublic(), aliceKeyAgree);
		SecretKey bobSecretKey = generateSecretKey(aliceKeyPair.getPublic(), bobKeyAgree);

		System.out.println(new String(aliceSecretKey.getEncoded()));
		System.out.println(new String(bobSecretKey.getEncoded()).length());

	}

	public static KeyPair genKeyPair() throws Exception {

		DHParameterSpec pspec = new DHParameterSpec(modulus, base);

		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH", "BC");
		keyGen.initialize(pspec);
		KeyPair newPair = keyGen.generateKeyPair();

		return newPair;
	}

	public static KeyAgreement genKeyAgreement(KeyPair currPair) throws Exception {

		KeyAgreement newAgreement = KeyAgreement.getInstance("DH", "BC");
		newAgreement.init(currPair.getPrivate());

		return newAgreement;
	}

	public static SecretKey generateSecretKey(PublicKey currPubKey, KeyAgreement currAgreement) throws Exception {

		currAgreement.doPhase(currPubKey, true);
		SecretKey newSecretKey = currAgreement.generateSecret("AES");
		return newSecretKey;
	}


}