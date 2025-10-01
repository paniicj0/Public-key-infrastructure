package com.info_security.is.crypto;

import com.info_security.is.model.Organization;
import com.info_security.is.service.UserService;
import com.info_security.is.service.OrgKeyService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.beans.factory.annotation.Autowired;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@Component
public class CryptoUtil {

    private static final SecureRandom RNG = new SecureRandom();
    private final SecretKeySpec masterKey; // AES-256

    @Autowired private UserService userService;
    @Autowired private OrgKeyService orgKeyService;

    // Master key iz env-a / konfiguracije
    public CryptoUtil(@Value("${app.crypto.masterKeyB64}") String base64MasterKey) {
        byte[] key = Base64.getDecoder().decode(base64MasterKey);
        if (key.length != 32) {
            throw new IllegalArgumentException("APP masterKey must be 32 bytes (base64 of 32B).");
        }
        this.masterKey = new SecretKeySpec(key, "AES");
    }

    /* ===================== PUBLIC API (POTPSI OSTAJU ISTI) ===================== */

    /** Enkriptuje PKCS#8 DER privatni ključ per-org ključem; vraća Base64(JSON) */
    public String encryptPrivateKey(PrivateKey pk) throws Exception {
        var me = userService.getCurrentUser();
        if (me == null || me.getOrganization() == null) {
            throw new SecurityException("No current organization context");
        }
        Organization org = me.getOrganization();
        SecretKey kOrg = orgKeyService.loadOrCreateOrgKeyFor(org);

        byte[] der = pk.getEncoded();

        // AES-GCM sa K_org + AAD org:<id>
        Blob blob = aesGcmEncrypt(kOrg, der, aad(org.getId()));

        // vraćamo JSON kao Base64 string (kompaktno)
        String json = toJson(blob);
        return Base64.getEncoder().encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }

    /** Dekriptuje enkriptovani PK (Base64(JSON)) koristeći org ključ */
    public PrivateKey decryptPrivateKey(String enc) throws Exception {
        var me = userService.getCurrentUser();
        if (me == null || me.getOrganization() == null) {
            throw new SecurityException("No current organization context");
        }
        Organization org = me.getOrganization();
        SecretKey kOrg = orgKeyService.loadOrCreateOrgKeyFor(org);

        byte[] raw = Base64.getDecoder().decode(enc);

        byte[] der;
        if (raw.length > 0 && raw[0] == '{') {
            // NOVI format: Base64(JSON)
            String json = new String(raw, java.nio.charset.StandardCharsets.UTF_8);
            Blob blob = fromJson(json);
            der = aesGcmDecrypt(kOrg, blob, aad(org.getId()));
        } else {
            // LEGACY format: Base64( iv(12) || ct||tag ) pod MASTER ključem
            if (raw.length < 12 + 16) throw new IllegalStateException("legacy blob too short");
            byte[] iv = java.util.Arrays.copyOfRange(raw, 0, 12);
            byte[] ctTag = java.util.Arrays.copyOfRange(raw, 12, raw.length);

            javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
            c.init(javax.crypto.Cipher.DECRYPT_MODE, masterKey, new javax.crypto.spec.GCMParameterSpec(128, iv));
            der = c.doFinal(ctTag);

            // (opciono) MIGRACIJA: re-wrap pod org ključ i sačuvaj nazad
            //   String migrated = Base64.getEncoder().encodeToString(
            //       toJson(aesGcmEncrypt(kOrg, der, aad(org.getId()))).getBytes(StandardCharsets.UTF_8));
            //   ... upiši migrated u repo za taj cert (ako ovde imaš entitet pri ruci)
        }

        return java.security.KeyFactory.getInstance("RSA")
                .generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(der));
    }

    /* ===================== AES-GCM helpers (JSON blob sa v/alg/iv/ct/tag) ===================== */

    // Jednostavan „blob“ – verziuj ga (v) i navedi alg
    private record Blob(int v, String alg, String iv, String ct, String tag) {}

    private Blob aesGcmEncrypt(SecretKey key, byte[] plaintext, byte[] aad) {
        try {
            byte[] iv = new byte[12];
            RNG.nextBytes(iv);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
            if (aad != null) c.updateAAD(aad);
            byte[] out = c.doFinal(plaintext);

            // poslednjih 16B je tag; split radi lakšeg JSON-a
            int tagLen = 16;
            byte[] ct = java.util.Arrays.copyOf(out, out.length - tagLen);
            byte[] tag = java.util.Arrays.copyOfRange(out, out.length - tagLen, out.length);

            return new Blob(1, "AES-256-GCM",
                    b64(iv), b64(ct), b64(tag));
        } catch (Exception e) {
            throw new IllegalStateException("AES-GCM encrypt failed", e);
        }
    }

    private byte[] aesGcmDecrypt(SecretKey key, Blob blob, byte[] aad) {
        try {
            byte[] iv  = b64d(blob.iv());
            byte[] ct  = b64d(blob.ct());
            byte[] tag = b64d(blob.tag());

            byte[] in = new byte[ct.length + tag.length];
            System.arraycopy(ct, 0, in, 0, ct.length);
            System.arraycopy(tag, 0, in, ct.length, tag.length);

            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
            if (aad != null) c.updateAAD(aad);
            return c.doFinal(in);
        } catch (Exception e) {
            throw new IllegalStateException("AES-GCM decrypt failed", e);
        }
    }

    private static byte[] aad(Long orgId) {
        return ("org:" + orgId).getBytes(StandardCharsets.UTF_8);
    }

    private static String toJson(Blob b) {
        // minimal JSON; za produkciju radije Jackson
        return String.format(java.util.Locale.ROOT,
                "{\"v\":%d,\"alg\":\"%s\",\"iv\":\"%s\",\"ct\":\"%s\",\"tag\":\"%s\"}",
                b.v(), b.alg(), b.iv(), b.ct(), b.tag());
    }

    private static Blob fromJson(String s) {
        // mini parser (ili Jackson)
        Map<String,String> m = new HashMap<>();
        for (String kv : s.replaceAll("[{}\"]", "").split(",")) {
            int i = kv.indexOf(':'); if (i<0) continue;
            m.put(kv.substring(0,i).trim(), kv.substring(i+1).trim());
        }
        return new Blob(Integer.parseInt(m.getOrDefault("v","1")),
                m.get("alg"), m.get("iv"), m.get("ct"), m.get("tag"));
    }

    private static String b64(byte[] a){ return Base64.getEncoder().encodeToString(a); }
    private static byte[] b64d(String s){ return Base64.getDecoder().decode(s); }
}
