package com.info_security.is.crypto;

import java.io.ByteArrayOutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class Keystores {


    public static byte[] toPkcs12(X509Certificate cert, PrivateKey priv, X509Certificate[] chain, char[] password) throws Exception {
        var ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("key", priv, password, chain != null ? chain : new X509Certificate[]{cert});
        try (var baos = new ByteArrayOutputStream()) {
            ks.store(baos, password);
            return baos.toByteArray();
        }
    }
}
