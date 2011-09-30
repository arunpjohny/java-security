package com.arun.security.signature;

import static com.arun.security.SecurityUtils.*;
import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import org.apache.commons.io.output.ByteArrayOutputStream;
import org.bouncycastle.util.encoders.Base64Encoder;

import com.arun.security.exception.PrivateKeyNotFoundException;

public class SignatureUtils {

	private static final String STRING_ENCODING = "UTF-8";

	public static boolean verify(File certificateFile, File signatureFile,
			File dataFile, String signAlgorithm) throws FileNotFoundException,
			IOException, CertificateException, NoSuchAlgorithmException,
			InvalidKeyException, SignatureException {
		byte[] sigToVerify = null;
		FileInputStream sigfis = new FileInputStream(signatureFile);
		try {
			sigToVerify = new byte[sigfis.available()];
			sigfis.read(sigToVerify);
		} finally {
			sigfis.close();
		}

		return verify(dataFile, sigToVerify, certificateFile, signAlgorithm);
	}

	public static boolean verify(File dataFile, byte[] sigToVerify,
			File certificateFile, String signAlgorithm)
			throws FileNotFoundException, IOException, CertificateException,
			NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		FileInputStream keyfis = new FileInputStream(certificateFile);
		try {
			byte[] encKey = new byte[keyfis.available()];
			keyfis.read(encKey);
		} finally {
			keyfis.close();
		}

		PublicKey pubKey = loadPublicKeyFromCertificate(certificateFile);

		Signature sig = Signature.getInstance(signAlgorithm);
		sig.initVerify(pubKey);

		FileInputStream datafis = new FileInputStream(dataFile);

		try {
			BufferedInputStream bufin = new BufferedInputStream(datafis);
			try {
				byte[] buffer = new byte[1024];
				int len;
				while (bufin.available() != 0) {
					len = bufin.read(buffer);
					sig.update(buffer, 0, len);
				}
			} finally {
				if (bufin != null) {
					bufin.close();
				}
			}
		} finally {
			if (datafis != null) {
				datafis.close();
			}

		}

		return sig.verify(sigToVerify);
	}

	public static boolean verifyUsingBase64Decode(File certificateFile,
			File signatureFile, File dataFile, String signAlgorithm)
			throws FileNotFoundException, IOException, CertificateException,
			NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		byte[] sigToVerify = null;
		FileInputStream sigfis = new FileInputStream(signatureFile);
		try {
			sigToVerify = new byte[sigfis.available()];
			sigfis.read(sigToVerify);
		} finally {
			sigfis.close();
		}

		ByteArrayOutputStream signStream = new ByteArrayOutputStream();
		new Base64Encoder().decode(sigToVerify, 0, sigToVerify.length,
				signStream);
		return verify(dataFile, signStream.toByteArray(), certificateFile,
				signAlgorithm);
	}

	public static boolean verify(File certificateFile, File signatureFile,
			String data, String signAlgorithm) throws FileNotFoundException,
			IOException, CertificateException, NoSuchAlgorithmException,
			InvalidKeyException, SignatureException {
		byte[] sigToVerify = null;
		FileInputStream sigfis = new FileInputStream(signatureFile);
		try {
			sigToVerify = new byte[sigfis.available()];
			sigfis.read(sigToVerify);
		} finally {
			sigfis.close();
		}

		return verify(data, sigToVerify, certificateFile, signAlgorithm);
	}

	public static boolean verify(String dataFile, byte[] sigToVerify,
			File certificateFile, String signAlgorithm)
			throws FileNotFoundException, IOException, CertificateException,
			NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		FileInputStream keyfis = new FileInputStream(certificateFile);
		try {
			byte[] encKey = new byte[keyfis.available()];
			keyfis.read(encKey);
		} finally {
			keyfis.close();
		}

		PublicKey pubKey = loadPublicKeyFromCertificate(certificateFile);

		Signature sig = Signature.getInstance(signAlgorithm);
		sig.initVerify(pubKey);

		sig.update(dataFile.getBytes(STRING_ENCODING));

		return sig.verify(sigToVerify);
	}

	public static boolean verifyUsingBase64Decode(File certificateFile,
			File signatureFile, String data, String signAlgorithm)
			throws FileNotFoundException, IOException, CertificateException,
			NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		byte[] sigToVerify = null;
		FileInputStream sigfis = new FileInputStream(signatureFile);
		try {
			sigToVerify = new byte[sigfis.available()];
			sigfis.read(sigToVerify);
		} finally {
			sigfis.close();
		}

		ByteArrayOutputStream signStream = new ByteArrayOutputStream();
		new Base64Encoder().decode(sigToVerify, 0, sigToVerify.length,
				signStream);
		return verify(data, signStream.toByteArray(), certificateFile,
				signAlgorithm);
	}

	public static void writeToFileUsingBase64Encode(byte[] realSig, File f2)
			throws FileNotFoundException, IOException {
		FileOutputStream sigfos2 = new FileOutputStream(f2);
		new Base64Encoder().encode(realSig, 0, realSig.length, sigfos2);
		sigfos2.close();
	}

	public static void writeToFile(File file, byte[] realSig)
			throws FileNotFoundException, IOException {
		FileOutputStream sigfos = new FileOutputStream(file);
		try {
			sigfos.write(realSig);
		} finally {
			sigfos.close();
		}
	}

	public static byte[] sign(File dataToSign, File keyStoreFile,
			String storePassword, String alias, String keyPassword,
			String signAlgorithm) throws IOException, KeyStoreException,
			NoSuchAlgorithmException, CertificateException,
			UnrecoverableKeyException, PrivateKeyNotFoundException,
			InvalidKeyException, FileNotFoundException, SignatureException {
		Signature dsa = null;

		KeyStore keyStore = loadKeyStore(keyStoreFile, storePassword);
		KeyPair pair = getKeyPair(keyStore, alias, keyPassword);
		PrivateKey priv = pair.getPrivate();

		dsa = Signature.getInstance(signAlgorithm);

		dsa.initSign(priv);

		FileInputStream fis = new FileInputStream(dataToSign);
		try {
			BufferedInputStream bufin = new BufferedInputStream(fis);
			try {
				byte[] buffer = new byte[1024];
				int len;
				while (bufin.available() != 0) {
					len = bufin.read(buffer);
					dsa.update(buffer, 0, len);
				}
			} finally {
				if (bufin != null) {
					bufin.close();
				}
			}
		} finally {
			if (fis != null) {
				fis.close();
			}
		}

		return dsa.sign();
	}

	public static byte[] sign(String dataToSign, File keyStoreFile,
			String storePassword, String alias, String keyPassword,
			String signAlgorithm) throws IOException, KeyStoreException,
			NoSuchAlgorithmException, CertificateException,
			UnrecoverableKeyException, PrivateKeyNotFoundException,
			InvalidKeyException, FileNotFoundException, SignatureException {
		Signature dsa = null;

		KeyStore keyStore = loadKeyStore(keyStoreFile, storePassword);
		KeyPair pair = getKeyPair(keyStore, alias, keyPassword);
		PrivateKey priv = pair.getPrivate();
		dsa = Signature.getInstance(signAlgorithm);
		dsa.initSign(priv);
		dsa.update(dataToSign.getBytes(STRING_ENCODING));
		return dsa.sign();
	}

}
