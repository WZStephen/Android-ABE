package com.cpabe.abe_lib.cpabe;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class AESCoder {

	private static byte[] getRawKey(byte[] seed) throws Exception {
		KeyGenerator kgen = KeyGenerator.getInstance("AES");
		SecureRandom sr = SecureRandom.getInstance("SHA1PRNG",new CryptoProvider());
		sr.setSeed(seed);
		kgen.init(128, sr); //tmp: 128,,, 192 and 256 bits may not be available
		SecretKey skey = kgen.generateKey();
		byte[] raw = skey.getEncoded();
		return raw;
	}

	public static byte[] encrypt(byte[] seed, byte[] plaintext) throws Exception {
		byte[] raw = getRawKey(seed);
		SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
		try {
			byte[] encrypted = cipher.doFinal(plaintext);
			return encrypted;
		}
		catch (Exception e){
			e.printStackTrace();
			return null;
		}
	}

	public static byte[] decrypt(byte[] seed, byte[] ciphertext) throws Exception {
		byte[] raw = getRawKey(seed);
		SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, skeySpec);
		try{
			byte[] decrypted = cipher.doFinal(ciphertext);
			return decrypted;
		}
		catch (Exception e){
			e.printStackTrace();
			return null;
		}
	}

}