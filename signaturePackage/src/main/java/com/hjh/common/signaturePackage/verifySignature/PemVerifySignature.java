package com.hjh.common.signaturePackage.verifySignature;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.security.PublicKey;
import java.security.Signature;

import com.hjh.common.signaturePackage.SecurityUtils;
import com.hjh.common.signaturePackage.common.SignatureUtil;
import com.hjh.common.signaturePackage.common.StreamToByteUtil;

public class PemVerifySignature {
	/**
	 * 检验pem签名
	 * 
	 * @author 陆国鸿
	 * @date 2016年12月21日
	 * @return boolean
	 */
	public static boolean verifyWithPemFilePath(byte[] data, byte[] signedData, String pemFilePath) throws Exception {
		try (FileInputStream fileInputStream = new FileInputStream(pemFilePath);) {
			boolean verify = verifyWithPemStream(data, signedData, fileInputStream);
			return verify;
		} catch (FileNotFoundException ex) {
			String errorMsg = String.format("文件无法读取,路径为[%s],异常信息为[%s]", pemFilePath, ex.getMessage());
			throw new RuntimeException(errorMsg, ex);
		} catch (SecurityException ex) {
			String errorMsg = String.format("读取文件没有权限,路径为[%s],异常信息为[%s]", pemFilePath, ex.getMessage());
			throw new RuntimeException(errorMsg, ex);
		}
	}

	/**
	 * 检验pem签名
	 * 
	 * @author 陆国鸿
	 * @date 2016年12月21日
	 * @return boolean
	 */
	public static boolean verifyWithPemBytes(byte[] data, byte[] signedData, byte[] pem) throws Exception {
		ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(pem);
		InputStream pemInputStream = (InputStream) byteArrayInputStream;
		boolean verify = verifyWithPemStream(data, signedData, pemInputStream);
		pemInputStream.close();
		return verify;
	}

	/**
	 * 检验pem签名,inputStream不会被关闭，请手动关闭
	 * 
	 * @author 陆国鸿
	 * @date 2016年12月21日
	 * @return boolean
	 */
	public static boolean verifyWithPemStream(byte[] data, byte[] signedData, InputStream pem) throws Exception {
		byte[] bytes = StreamToByteUtil.getByte(pem);
		Signature instance = SignatureUtil.getSignature();
		PublicKey publicKey = SecurityUtils.getPublicKeyFromPem(bytes);
		instance.initVerify(publicKey);
		instance.update(data);
		return instance.verify(signedData);
	}
}
