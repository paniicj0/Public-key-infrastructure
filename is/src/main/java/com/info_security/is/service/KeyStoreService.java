package com.info_security.is.service;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.X509Certificate;

@Service
@RequiredArgsConstructor
public class KeyStoreService {

    @Value("${pki.keystore.dir}")
    private String ksDir;

    @Value("${pki.keystore.password}")
    private String ksPassword;

    private File fileForCert(Long certId) {
        File dir = new File(ksDir);
        if (!dir.exists()) dir.mkdirs();
        return new File(dir, "cert-" + certId + ".p12");
    }

    public void store(Long certId, KeyPair keyPair, X509Certificate[] chain) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, ksPassword.toCharArray());
        ks.setKeyEntry("key", keyPair.getPrivate(), ksPassword.toCharArray(), chain);
        try (FileOutputStream fos = new FileOutputStream(fileForCert(certId))) {
            ks.store(fos, ksPassword.toCharArray());
        }
    }

    public PrivateKey loadPrivateKey(Long certId) throws Exception {
        File f = fileForCert(certId);
        if (!f.exists()) throw new IllegalStateException("Keystore for cert " + certId + " not found.");
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(Files.newInputStream(f.toPath()), ksPassword.toCharArray());
        Key key = ks.getKey("key", ksPassword.toCharArray());
        if (!(key instanceof PrivateKey)) throw new IllegalStateException("No private key entry.");
        return (PrivateKey) key;
    }
}
