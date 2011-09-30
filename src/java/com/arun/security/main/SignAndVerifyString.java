package com.arun.security.main;

import static com.arun.security.main.Constants.BASE_FOLDER;
import static com.arun.security.main.Constants.CERTIFICATE_FILE;
import static com.arun.security.main.Constants.*;
import static com.arun.security.main.Constants.KEYSTORE_FILE;
import static com.arun.security.main.Constants.KEY_ALIAS;
import static com.arun.security.main.Constants.KEY_FOLDER;
import static com.arun.security.main.Constants.KEY_PASSWORD;
import static com.arun.security.main.Constants.SIGNATURE_ALGORITHM;
import static com.arun.security.main.Constants.SIGNATURE_FILE;
import static com.arun.security.main.Constants.STORE_PASSWOD;
import static com.arun.security.signature.SignatureUtils.sign;
import static com.arun.security.signature.SignatureUtils.verify;
import static com.arun.security.signature.SignatureUtils.writeToFile;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import com.arun.security.exception.PrivateKeyNotFoundException;

public class SignAndVerifyString {
	public static void main(String[] args) throws UnrecoverableKeyException,
			InvalidKeyException, KeyStoreException, NoSuchAlgorithmException,
			CertificateException, FileNotFoundException, SignatureException,
			IOException, PrivateKeyNotFoundException {
		File keyStoreFile = new File(KEY_FOLDER, KEYSTORE_FILE);
		File certificateFile = new File(KEY_FOLDER, CERTIFICATE_FILE);
		File signatureFile = new File(BASE_FOLDER, SIGNATURE_FILE);
		String storePassword = STORE_PASSWOD;
		String alias = KEY_ALIAS;
		String keyPassword = KEY_PASSWORD;
		String signAlgorithm = SIGNATURE_ALGORITHM;

		byte[] realSig = sign(INPUT_TEXT, keyStoreFile, storePassword, alias,
				keyPassword, signAlgorithm);

		writeToFile(signatureFile, realSig);

		System.out.println("signature verifies: "
				+ verify(certificateFile, signatureFile, INPUT_TEXT,
						signAlgorithm));
	}
}
