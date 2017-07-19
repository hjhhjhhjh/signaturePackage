package com.hjh.common.signaturePackage.verifySignature;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.PublicKey;
import java.security.Signature;

import com.hjh.common.signaturePackage.SecurityUtils;
import com.hjh.common.signaturePackage.common.SignatureUtil;

public class CerVerifySignature {

	/**
	 * 使用cer检验签名
	 * 
	 * @author 陈航，陆国鸿
	 * @date 2016年12月12日
	 * @return boolean
	 */
	public static boolean verifyWithCerStream(byte[] data, byte[] signedData, InputStream cer) throws Exception {
		Signature instance = SignatureUtil.getSignature();
		PublicKey publicKey = SecurityUtils.getPublicKeyFromCer(cer);
		instance.initVerify(publicKey);
		instance.update(data);
		return instance.verify(signedData);
	}

	/**
	 * 使用cer检验签名
	 * 
	 * @author 陆国鸿
	 * @date 2016年12月12日
	 * @return boolean
	 */
	public static boolean verifyWithCerBytes(byte[] data, byte[] signedData, byte[] cerBytes) throws Exception {
		try (ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(cerBytes);) {
			boolean verify = verifyWithCerStream(data, signedData, byteArrayInputStream);
			return verify;
		}
	}

	/**
	 * 使用cer检验签名
	 * 
	 * @author 陆国鸿
	 * @date 2016年12月12日
	 * @return boolean
	 */
	public static boolean verifyWithCerFilePath(byte[] data, byte[] signedData, String cerFilePath) throws Exception {
		try (FileInputStream cerInputStream = new FileInputStream(cerFilePath);) {
			boolean verify = verifyWithCerStream(data, signedData, cerInputStream);
			return verify;
		}

	}

}
