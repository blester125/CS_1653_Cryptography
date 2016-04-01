import org.apache.commons.codec.*;

import com.warrenstrange.googleauth.*;
import com.warrenstrange.googleauth.GoogleAuthenticatorConfig.GoogleAuthenticatorConfigBuilder;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

import java.math.BigInteger;
import java.util.List;
import java.util.concurrent.TimeUnit;

public class TwoAuthTest {

	public static void main(String args[]) {

		//--------------------------------------------------

        GoogleAuthenticatorConfigBuilder gacb =
                new GoogleAuthenticatorConfigBuilder()
                        .setKeyRepresentation(KeyRepresentation.BASE64);
        GoogleAuthenticator googleAuthenticator = new GoogleAuthenticator(gacb.build());

        final GoogleAuthenticatorKey key =
                googleAuthenticator.createCredentials();
        final String secret = key.getKey();
        final List<Integer> scratchCodes = key.getScratchCodes();

        String otpAuthURL = GoogleAuthenticatorQRGenerator.getOtpAuthURL("Test Org.", "test@prova.org", key);

        System.out.println("Please register (otpauth uri): " + otpAuthURL);
        System.out.println("Base64-encoded secret key is " + secret);

        for (Integer i : scratchCodes) {
            System.out.println("Scratch code: " + i);
        }
	}

	private static byte[] hexStr2Bytes(String hex) {
        // Adding one byte to get the right conversion
        // Values starting with "0" can be converted
        byte[] bArray = new BigInteger("10" + hex, 16).toByteArray();

        // Copy all the REAL bytes, not the "first"
        byte[] ret = new byte[bArray.length - 1];
        System.arraycopy(bArray, 1, ret, 0, ret.length);

        return ret;
    }


}