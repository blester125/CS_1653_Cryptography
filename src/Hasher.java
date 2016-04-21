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

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Security;
import java.security.SecureRandom;

import java.util.*;

import javax.crypto.Mac;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Hasher {

	public static byte[] hash(Object obj) {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256", "BC");
			md.update(obj.toString().getBytes("UTF-8"));
			return md.digest();
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	public static byte[] hash(byte[] obj) {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256", "BC");
			md.update(obj);
			return md.digest();
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	public static byte[] generateHMAC(Key k, byte[] obj) {
		try {		
			Mac mac = Mac.getInstance("HmacSHA256", "BC");
			mac.init(k);
			byte[] raw = mac.doFinal(obj);
			return raw;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}	
	}
	
	

	public static boolean verifyHash(byte[] recvHash, Object obj) {
		byte[] madeHash = hash(obj);
		return MessageDigest.isEqual(recvHash, madeHash);
	}

	public static boolean verifyHMAC(byte[] recvHMAC, byte[] madeHMAC) {
		return MessageDigest.isEqual(recvHMAC, madeHMAC);
	}

	public static byte[] convertToByteArray(Object object) {
		try 
			(ByteArrayOutputStream bos = new ByteArrayOutputStream();
			ObjectOutput out = new ObjectOutputStream(bos)) 
		{
			out.writeObject(object);
			return bos.toByteArray();
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	public static byte[] concatenateArrays(byte[] arr1, byte[] arr2) {
		byte[] arr3 = new byte[arr1.length + arr2.length];
		for (int i = 0; i < arr1.length; i++) {
			arr3[i] = arr1[i];
		}
		for (int i = 0; i < arr2.length; i++) {
			arr3[i + arr1.length] = arr2[i];
		}
		return arr3;
	}

	public static byte[] bruteForce(int size, byte[] goal) {
		byte[] answer = new byte[size];
		//answer = hardcode(goal);
		//return answer;
		ArrayList<Character> list = new ArrayList<Character>();
		bruteForce(size, list, goal);
		answer = convertListToByte(list);
		return answer;
	}

	private static byte[] hardcode(byte[] goal) {
		byte[] answer = new byte[4];
		for (int i = 'A'; i <= 'l'; i++) {
			for (int j = 'A'; j <= 'l'; j++) {
				for (int k = 'A'; k <= 'l'; k++) {
					for (int l = 'A'; l <= 'l'; l++) {
						//for (int m = 'A'; m <= 'Z'; m++) {
							answer[0] = (byte)i;
							answer[1] = (byte)j;
							answer[2] = (byte)k;
							answer[3] = (byte)l;
						//	answer[4] = (byte)m;
							//System.out.println(new String(answer));
							//System.out.println(new String(hash(answer)));
							if (MessageDigest.isEqual(hash(answer), goal)) {
								return answer;
							}
						//}
					}
				}
			}
		}
		return null;
	}

	public static boolean bruteForce(
								int size,
								ArrayList<Character> answer, 
								byte[] goal) {
		// for (Character c : answer) {
		// 	System.out.print(c);
		// }
		//System.out.println("------------------\n");
		if (answer.size() == size) {
			byte[] test = new byte[size];
			test = convertListToByte(answer);
			//System.out.println(new String(test));
			if (MessageDigest.isEqual(hash(test), goal)) {
				return true;
			}
			return false;
		}
		for (int i = 'A'; i <= 'l'; i++) {
			answer.add((char)i);
			if (bruteForce(size, answer, goal)) {
				return true;
			} else {
				answer.remove(answer.size() - 1);
			}
		}
		return false;
	}

	private static byte[] convertListToByte(ArrayList<Character> list) {
		byte[] answer = new byte[list.size()];
		int i = 0;
		for (char c : list) {
			answer[i] = (byte)c;
			i++;
		}
		return answer;
	}

	public static byte[] generatePuzzle(int size) {
		SecureRandom rand = new SecureRandom();
		byte[] answer = new byte[size];
		for (int i = 0; i < size; i++) {
			answer[i] = (byte)(rand.nextInt('l' - 'A' + 1) + 'A');
		}
		//System.out.println(new String(answer));
		return answer;
	}

	public static void main(String args[]) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		// KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
		// keyGen.initialize(2048);
		// KeyPair keyPair = keyGen.generateKeyPair();
		// System.out.println(keyPair.getPublic().toString());
		// System.out.println(keyPair.getPublic().getEncoded());
		//for (int i = 0; i < 4; i++) {
			byte[] answer = {'A','B','C','X', 'l', 'e'};
			long now = System.currentTimeMillis();
			byte[] hashcode = hash(answer);
			byte[] output = bruteForce(6, hashcode);
			System.out.println(new String(answer));
			System.out.println(new String(output));
			System.out.println(System.currentTimeMillis() - now);
			// byte[] answer2 = {'l','l','l','l'};
			// now = System.currentTimeMillis();
			// hashcode = hash(answer2);
			// output = bruteForce(4, hashcode);
			// System.out.println(new String(answer2));
			// System.out.println(new String(output));
			// System.out.println(System.currentTimeMillis() - now);
		//}
	}
}
