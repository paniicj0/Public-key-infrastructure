package com.info_security.is.service;

import com.info_security.is.crypto.MasterKeyProvider;
import com.info_security.is.model.Organization;
import com.info_security.is.repository.OrganizationRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class OrgKeyService {

    private final OrganizationRepository orgRepo;
    private final MasterKeyProvider masterKeyProvider;
    private static final SecureRandom RNG = new SecureRandom();

    @Transactional
    public SecretKey loadOrCreateOrgKeyFor(Organization org) {
        if (org.getOrgKeyBlob() == null || org.getOrgKeyBlob().isBlank()) {
            byte[] raw = new byte[32]; RNG.nextBytes(raw);
            SecretKey kOrg = new SecretKeySpec(raw, "AES");
            String blob = wrapWithMasterKey(kOrg, aad(org.getId()));
            org.setOrgKeyBlob(blob);
            orgRepo.save(org);
            return kOrg;
        }
        return unwrapWithMasterKey(org.getOrgKeyBlob(), aad(org.getId()));
    }

    // --- wrap/unwrap using MASTER KEY (JSON blob) ---
    private String wrapWithMasterKey(SecretKey orgKey, byte[] aad) {
        return toJson(aesGcmEncrypt(masterKeyProvider.get(), orgKey.getEncoded(), aad));
    }
    private SecretKey unwrapWithMasterKey(String blobJson, byte[] aad) {
        Blob b = fromJson(blobJson);
        byte[] raw = aesGcmDecrypt(masterKeyProvider.get(), b, aad);
        return new SecretKeySpec(raw, "AES");
    }

    private record Blob(int v, String alg, String iv, String ct, String tag) {}

    private static Blob aesGcmEncrypt(SecretKey key, byte[] plaintext, byte[] aad) {
        try {
            byte[] iv = new byte[12]; RNG.nextBytes(iv);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
            if (aad != null) c.updateAAD(aad);
            byte[] out = c.doFinal(plaintext);

            int tagLen = 16;
            byte[] ct = java.util.Arrays.copyOf(out, out.length - tagLen);
            byte[] tag = java.util.Arrays.copyOfRange(out, out.length - tagLen, out.length);

            return new Blob(1, "AES-256-GCM",
                    b64(iv), b64(ct), b64(tag));
        } catch (Exception e) {
            throw new IllegalStateException("wrap failed", e);
        }
    }

    private static byte[] aesGcmDecrypt(SecretKey key, Blob blob, byte[] aad) {
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
            throw new IllegalStateException("unwrap failed", e);
        }
    }

    private static byte[] aad(Long orgId) {
        return ("org:" + orgId).getBytes(StandardCharsets.UTF_8);
    }

    private static String toJson(Blob b) {
        return String.format(java.util.Locale.ROOT,
                "{\"v\":%d,\"alg\":\"%s\",\"iv\":\"%s\",\"ct\":\"%s\",\"tag\":\"%s\"}",
                b.v(), b.alg(), b.iv(), b.ct(), b.tag());
    }

    private static Blob fromJson(String s) {
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
