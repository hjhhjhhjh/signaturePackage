/**
 * 
 */
package com.hjh.common.signaturePackage.signature;

import java.io.InputStream;
import java.security.PrivateKey;
import java.security.Signature;

import com.hjh.common.signaturePackage.SecurityUtils;
import com.hjh.common.signaturePackage.common.SignatureUtil;

/**
 * 数字证书工具
 * 
 * @author 陈航，陆国鸿
 * @date 2016年12月12日 上午10:46:02
 * @Copyright (C) 2016, frontpay.cn
 */
public class PfxSignature {

	/**
	 * 签名
	 * 
	 * @author 陈航，陆国鸿
	 * @date
	 * @return String
	 */
	public static byte[] signDataWithPfxStreamToByteArray(byte[] data, String password, InputStream pfxStream)
			throws Exception {
		Signature signature = SignatureUtil.getSignature();
		PrivateKey privateKey = SecurityUtils.getPrivateKeyFromPfx(pfxStream, password);
		signature.initSign(privateKey);
		signature.update(data);
		return signature.sign();
	}

	

}
