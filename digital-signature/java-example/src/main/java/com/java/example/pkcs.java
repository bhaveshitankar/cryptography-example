package com.java.example;

import java.io.File;
import java.io.FileReader;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

public class pkcs {

	public static void main(String[] args) {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		try {
			PrivateKey privateK = getPrivateKey("../key/priv.pem");
			if (privateK == null)
				System.out.println("NULL");
			PublicKey publicK = getPublicKey("../key/pub.pem");

			String message = "test";
			String signature = Sign(privateK, message);

			System.out.println("Signed: " + signature);

			System.out.println(Verify(publicK, signature, message));
		} catch (Exception ex) {
			System.out.println(ex.toString());
		}

	}

	public static PublicKey getPublicKey(String fileName) {
		try {
			KeyFactory factory = KeyFactory.getInstance("RSA");
			File file = new File(fileName);
			try (FileReader keyReader = new FileReader(file); PemReader pemReader = new PemReader(keyReader)) {
				PemObject pemObject = pemReader.readPemObject();
				byte[] content = pemObject.getContent();
				X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(content);
				PublicKey publicKey = factory.generatePublic(pubKeySpec);
				return publicKey;
			} catch (Exception exx) {
				System.out.println(exx.toString());
			}
		} catch (Exception ex) {
			System.out.println(ex.toString());
		}

		return null;
	}

	public static PrivateKey getPrivateKey(String fileName) {
		try {
			KeyFactory factory = KeyFactory.getInstance("RSA");
			File file = new File(fileName);
			try (FileReader keyReader = new FileReader(file); PemReader pemReader = new PemReader(keyReader)) {
				PemObject pemObject = pemReader.readPemObject();
				byte[] content = pemObject.getContent();
				PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(content);
				PrivateKey privateKey = factory.generatePrivate(privateKeySpec);
				return privateKey;
			} catch (Exception exx) {
				System.out.println(exx.toString());
			}
		} catch (Exception ex) {
			System.out.println(ex.toString());
		}

		return null;
	}

	public static boolean Verify(PublicKey publicKey, String signatureStr, String msg) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, SignatureException {
		byte[] sigBytes = Base64.getDecoder().decode(signatureStr);

		Signature signature = Signature.getInstance("RSASSA-PSS", "BC");
		RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;

		int saltLen = rsaPublicKey.getModulus().bitLength() / 8 - 32 - 2;

		PSSParameterSpec spec = new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, saltLen, 1);

		signature.setParameter(spec);
		signature.initVerify(publicKey);
		signature.update(msg.getBytes(StandardCharsets.UTF_8));

		return signature.verify(sigBytes);
	}

	public static String Sign(PrivateKey privateKey, String msg) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, SignatureException, InvalidKeyException {
		Signature signature = Signature.getInstance("RSASSA-PSS", "BC");

		java.security.interfaces.RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) privateKey;

		// Calculate dynamic salt length: modulus byte length - digest length - 2
		int saltLen = rsaPrivateKey.getModulus().bitLength() / 8 - 32 - 2;

		PSSParameterSpec pssSpec = new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, saltLen, 1);

		signature.setParameter(pssSpec);
		signature.initSign(rsaPrivateKey);
		signature.update(msg.getBytes(StandardCharsets.UTF_8));

		byte[] sigBytes = signature.sign();
        return Base64.getEncoder().encodeToString(sigBytes);
	}
}

