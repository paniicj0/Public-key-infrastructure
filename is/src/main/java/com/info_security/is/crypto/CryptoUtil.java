package com.info_security.is.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.security.PrivateKey;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class CryptoUtil {
    private static final SecureRandom RNG = new SecureRandom();
    private final SecretKeySpec masterKey; // AES-256

    public CryptoUtil(String base64MasterKey) {
        byte[] key = Base64.getDecoder().decode(base64MasterKey);
        if (key.length != 32) {
            throw new IllegalArgumentException("MASTER_KEY_B64 must decode to 32 bytes (AES-256).");
        }
        this.masterKey = new SecretKeySpec(key, "AES");
    }

    /** Enkriptuje PKCS8 DER privatni ključ; vraća Base64(iv|ciphertext|tag) */
    public String encryptPrivateKey(PrivateKey pk) throws Exception {
        byte[] plain = pk.getEncoded(); // PKCS8 DER
        byte[] iv = new byte[12];
        RNG.nextBytes(iv);

        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, masterKey, new GCMParameterSpec(128, iv));
        byte[] ct = c.doFinal(plain);

        ByteBuffer bb = ByteBuffer.allocate(iv.length + ct.length);
        bb.put(iv).put(ct);
        return Base64.getEncoder().encodeToString(bb.array());
    }

    /** Dekriptuje Base64(iv|ciphertext|tag) u PrivateKey (RSA PKCS8) */
    public PrivateKey decryptPrivateKey(String enc) throws Exception {
        byte[] data = Base64.getDecoder().decode(enc);
        ByteBuffer bb = ByteBuffer.wrap(data);
        byte[] iv = new byte[12]; bb.get(iv);
        byte[] ct = new byte[bb.remaining()]; bb.get(ct);

        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, masterKey, new GCMParameterSpec(128, iv));
        byte[] plain = c.doFinal(ct);

        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(plain));
    }
}
