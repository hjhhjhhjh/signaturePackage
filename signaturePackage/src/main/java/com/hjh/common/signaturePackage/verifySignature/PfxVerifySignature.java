package com.hjh.common.signaturePackage.verifySignature;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.PublicKey;
import java.security.Signature;

import com.hjh.common.signaturePackage.SecurityUtils;
import com.hjh.common.signaturePackage.common.SignatureUtil;

public class PfxVerifySignature {
	/**
	 * 使用pfx检验签名
	 * 
	 * @author 陆国鸿
	 * @date 2016年12月12日
	 * @return boolean
	 */
	public static boolean verifyWithPfxBytes(byte[] data, byte[] signedData, byte[] pfx, String password)
			throws Exception {
		ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(pfx);
		InputStream pfxInputStream = (InputStream) byteArrayInputStream;
		boolean verify = verifyWithPfxStream(data, signedData, pfxInputStream, password);
		pfxInputStream.close();
		return verify;
	}

	/**
	 * 使用pfx检验签名
	 * 
	 * @author 陆国鸿
	 * @date 2016年12月12日
	 * @return boolean
	 */
	public static boolean verifyWithPfxFilePath(byte[] data, byte[] signedData, String pfxFilePath, String password)
			throws Exception {
		FileInputStream pfxInputStream = new FileInputStream(pfxFilePath);
		boolean verify = verifyWithPfxStream(data, signedData, pfxInputStream, password);
		pfxInputStream.close();
		return verify;
	}

	/**
	 * 使用pfx检验签名
	 * 
	 * @author 陆国鸿
	 * @date 2016年12月12日
	 * @return boolean
	 */
	public static boolean verifyWithPfxStream(byte[] data, byte[] signedData, InputStream pfxInputStream,
			String password) throws Exception {
		Signature instance = SignatureUtil.getSignature();
		PublicKey publicKey = SecurityUtils.getPublicKeyFromPfx(pfxInputStream, password);
		instance.initVerify(publicKey);
		instance.update(data);
		return instance.verify(signedData);
	}
}
