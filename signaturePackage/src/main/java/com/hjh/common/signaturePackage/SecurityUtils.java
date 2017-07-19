/**
 * 
 */
package com.hjh.common.signaturePackage;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Enumeration;

/**
 * 数字证书安全组件
 * 
 * @author 陈航，陆国鸿
 * @date 2016年12月12日 下午1:44:11
 * @Copyright (C) 2016, frontpay.cn
 */
public class SecurityUtils {

	/**
	 * 获取私钥
	 * 
	 * @author 陆国鸿
	 * @date 2016年12月12日
	 * @return PrivateKey
	 */
	public static PrivateKey getPrivateKeyFromPfx(String fileName, String password) throws Exception {
		try (FileInputStream stream = new FileInputStream(fileName)) {
			return SecurityUtils.getPrivateKeyFromPfx(stream, password);
		} catch (FileNotFoundException ex) {
			String errorMsg = String.format("文件无法读取,路径为[%s],异常信息为[%s]", fileName, ex.getMessage());
			throw new RuntimeException(errorMsg, ex);
		} catch (SecurityException ex) {
			String errorMsg = String.format("读取文件没有权限,路径为[%s],异常信息为[%s]", fileName, ex.getMessage());
			throw new RuntimeException(errorMsg, ex);
		}
	}

	/**
	 * 获取私钥，inputStream不会被关闭，请手动关闭
	 * 
	 * @author 陈航，陆国鸿
	 * @date 2016年12月12日
	 * @return PrivateKey
	 */
	public static PrivateKey getPrivateKeyFromPfx(InputStream inputStream, String password) throws Exception {
		KeyStore store = KeyStore.getInstance("PKCS12");
		store.load(inputStream, password.toCharArray());
		@SuppressWarnings({ "rawtypes" })
		Enumeration aliases = store.aliases();
		String alias = (String) aliases.nextElement();
		return ((PrivateKey) store.getKey(alias, password.toCharArray()));
	}

	/**
	 * 从pfx中获取公钥
	 * 
	 * @author 陆国鸿
	 * @date 2016年12月13日
	 * @return PublicKey
	 */
	public static PublicKey getPublicKeyFromPfx(InputStream inputStream, String password) throws Exception {
		KeyStore store = KeyStore.getInstance("PKCS12");
		store.load(inputStream, password.toCharArray());
		@SuppressWarnings({ "rawtypes" })
		Enumeration aliases = store.aliases();
		String alias = (String) aliases.nextElement();
		java.security.cert.Certificate certificate = store.getCertificate(alias);
		PublicKey publicKey = certificate.getPublicKey();
		return publicKey;
	}

	/**
	 * 获取公钥
	 * 
	 * @author 陆国鸿
	 * @date 2016年12月12日
	 * @return PublicKey
	 */
	public static PublicKey getPublicKeyFromCer(String fileName) throws Exception {
		try (FileInputStream stream = new FileInputStream(fileName)) {
			return SecurityUtils.getPublicKeyFromCer(stream);
		} catch (FileNotFoundException ex) {
			String errorMsg = String.format("文件无法读取,路径为[%s],异常信息为[%s]", fileName, ex.getMessage());
			throw new RuntimeException(errorMsg, ex);
		} catch (SecurityException ex) {
			String errorMsg = String.format("读取文件没有权限,路径为[%s],异常信息为[%s]", fileName, ex.getMessage());
			throw new RuntimeException(errorMsg, ex);
		}
	}

	/**
	 * 获取公钥，inputStream不会被关闭，请手动关闭
	 * 
	 * @author 陈航，陆国鸿
	 * @date 2016年12月12日
	 * @return PublicKey
	 */
	public static PublicKey getPublicKeyFromCer(InputStream inputSteam) throws Exception {
		CertificateFactory factory = CertificateFactory.getInstance("X.509");
		return (factory.generateCertificate(inputSteam).getPublicKey());
	}

	/**
	 * 从pem中获取公钥
	 * 
	 * @author 陆国鸿
	 * @date 2016年12月21日
	 * @return PublicKey
	 */
	public static PublicKey getPublicKeyFromPem(String pemFilePath) throws Exception {
		@SuppressWarnings("resource")
		FileReader fileReader = new FileReader(pemFilePath);
		ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream(4096);
		int tmpInt = 0;
		while (-1 != (tmpInt = fileReader.read())) {
			byteArrayOutputStream.write(tmpInt);
		}
		byte[] bytes = byteArrayOutputStream.toByteArray();
		return getPublicKeyFromPem(bytes);
	}

	/**
	 * 从pem中获取公钥
	 * 
	 * @param pem
	 *            从pem文件中直接读取的字节数组
	 * @author 陆国鸿
	 * @date 2016年12月21日
	 * @return PublicKey
	 * @throws Exception
	 */
	public static PublicKey getPublicKeyFromPem(byte[] pem) throws Exception {
		String publicKey = new String(pem);
		publicKey = publicKey.replace("-----BEGIN PUBLIC KEY-----", "");
		publicKey = publicKey.replace("-----END PUBLIC KEY-----", "");
		byte[] encodedKey = Base64.getDecoder().decode(publicKey);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");

		try {
			return keyFactory.generatePublic(new X509EncodedKeySpec(encodedKey));
		} catch (Exception e) {
			throw new RuntimeException("公钥不符合规范:" + e.getMessage(), e);
		}
	}

}
