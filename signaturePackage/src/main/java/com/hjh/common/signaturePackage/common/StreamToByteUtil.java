package com.hjh.common.signaturePackage.common;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

public class StreamToByteUtil {
	public static byte[] getByte(InputStream stream) throws IOException {
		try (ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();) {
			int tmpInt = 0;
			while (-1 != (tmpInt = stream.read())) {
				byteArrayOutputStream.write(tmpInt);
			}
			byte[] bytes = byteArrayOutputStream.toByteArray();
			return bytes;
		}
	}
}
