package com.github.wxpay.sdk;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.Security;
import java.util.Base64;

public class RefundNotifyUtil {
    public static String ALGORITHM_MODE_PADDING = "AES/ECB/PKCS7Padding";
    public static String ALGORITHM = "AES";

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static byte[] base64Decode(String data) {
        return Base64.getDecoder().decode(data);
    }

    public static String decript(String data, String sKey) throws
            Exception {
//        final KeyGenerator generator = KeyGenerator.getInstance("AES");
//        generator.init(256, new SecureRandom(sKey.getBytes()));
//        final SecretKey secretKey = generator.generateKey();
//        byte[] encodeFormat = secretKey.getEncoded();
        final SecretKeySpec secretKeySpec = new SecretKeySpec(WXPayUtil.MD5(sKey).getBytes(), ALGORITHM);

        final Cipher cipher = Cipher.getInstance(ALGORITHM_MODE_PADDING);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
        byte[] encryptedData = base64Decode(data);

        byte[] original = cipher.doFinal(encryptedData);
        return new String(original, "utf-8");
    }
}
