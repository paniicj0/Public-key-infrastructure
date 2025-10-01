package com.info_security.is.crypto;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

@Component
public class MasterKeyProvider {
    private final SecretKey masterKey;

    public MasterKeyProvider(@Value("${app.crypto.masterKeyB64}") String b64) {
        byte[] raw = Base64.getDecoder().decode(b64);
        if (raw.length != 32) {
            throw new IllegalArgumentException("APP_MASTER_KEY_B64 must be base64 of 32 bytes (AES-256).");
        }
        this.masterKey = new SecretKeySpec(raw, "AES");
    }

    public SecretKey get() {
        return masterKey;
    }
}
