package com.hjh.common.signaturePackage.common;

import java.security.NoSuchAlgorithmException;
import java.security.Signature;

public class SignatureUtil {
	static String ALGORITHM = "SHA1withRSA";
	
	static Signature instance = null;

	public static Signature getSignature() throws NoSuchAlgorithmException {
		if (instance == null) {
			instance = Signature.getInstance(getAlgorithm());
		}
		return instance;
	}
	
	public static String getAlgorithm() {
		return ALGORITHM;
	}
}
