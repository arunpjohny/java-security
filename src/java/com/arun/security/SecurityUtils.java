package com.arun.security;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

import com.arun.security.exception.PrivateKeyNotFoundException;

public class SecurityUtils {
	public static KeyStore loadKeyStore(File file, String storePassword)
			throws IOException, KeyStoreException, NoSuchAlgorithmException,
			CertificateException {
		return loadKeyStore(KeyStore.getDefaultType(), file, storePassword);
	}

	public static KeyStore loadKeyStore(String storeType, File file,
			String storePassword) throws IOException, KeyStoreException,
			NoSuchAlgorithmException, CertificateException {
		FileInputStream is = new FileInputStream(file);
		try {
			KeyStore keystore = KeyStore.getInstance(storeType);
			keystore.load(is,
					storePassword == null ? null : storePassword.toCharArray());

			return keystore;
		} finally {
			is.close();
		}
	}

	public static KeyPair getKeyPair(KeyStore keyStore, String alias,
			String keyPassword) throws UnrecoverableKeyException,
			KeyStoreException, NoSuchAlgorithmException,
			PrivateKeyNotFoundException {
		Key key = getKey(keyStore, alias, keyPassword);
		if (key instanceof PrivateKey) {
			return new KeyPair(getPublicKey(keyStore, alias), (PrivateKey) key);
		} else {
			throw new PrivateKeyNotFoundException("The given key " + alias
					+ " is not a private key.");
		}
	}

	public static PublicKey getPublicKey(KeyStore keyStore, String alias)
			throws KeyStoreException {
		return keyStore.getCertificate(alias).getPublicKey();
	}

	public static Key getKey(KeyStore keyStore, String alias, String keyPassword)
			throws KeyStoreException, NoSuchAlgorithmException,
			UnrecoverableKeyException {
		return keyStore.getKey(alias,
				keyPassword == null ? null : keyPassword.toCharArray());
	}

	public static PublicKey loadPublicKeyFromCertificate(File certificateFile)
			throws FileNotFoundException, CertificateException, IOException {
		return loadPublicKeyFromCertificate(certificateFile, "X.509");
	}

	public static PublicKey loadPublicKeyFromCertificate(File certificateFile,
			String certificateType) throws FileNotFoundException,
			CertificateException, IOException {
		PublicKey publicKey = null;
		FileInputStream fis = new FileInputStream(certificateFile);
		try {

			CertificateFactory cf = CertificateFactory
					.getInstance(certificateType);
			java.security.cert.Certificate cert = cf.generateCertificate(fis);
			publicKey = cert.getPublicKey();
		} finally {
			fis.close();
		}
		return publicKey;
	}

}
