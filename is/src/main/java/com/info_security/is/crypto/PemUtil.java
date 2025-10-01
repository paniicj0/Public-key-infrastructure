package com.info_security.is.crypto;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;

import java.io.*;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public final class PemUtil {
    private PemUtil(){}

    public static String certToPem(X509Certificate cert) throws IOException {
        try (StringWriter sw = new StringWriter();
             JcaPEMWriter pw = new JcaPEMWriter(sw)) {
            pw.writeObject(cert);
            pw.flush();
            return sw.toString();
        }
    }

    public static X509Certificate pemToCert(String pem) throws Exception {
        try (Reader r = new StringReader(pem);
             PEMParser pp = new PEMParser(r)) {
            Object obj = pp.readObject();
            if (!(obj instanceof X509CertificateHolder holder)) {
                throw new IllegalArgumentException("Not an X509 certificate PEM");
            }
            return new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);
        }
    }

    public static X509Certificate readX509(String pem) throws Exception {
        try (var r = new StringReader(pem); var p = new PEMParser(r)) {
            var obj = p.readObject();
            var conv = new JcaX509CertificateConverter().setProvider("BC");
            if (obj instanceof X509CertificateHolder h) return conv.getCertificate(h);
            throw new IllegalArgumentException("Not an X509 PEM");
        }
    }
    public static PrivateKey readPrivateKey(String pem) throws Exception {
        // ako čuvaš enkodovano, ovde prvo dekripcija pa parse
        try (var r = new StringReader(pem); var p = new PEMParser(r)) {
            Object o = p.readObject();
            var conv = new JcaPEMKeyConverter().setProvider("BC");
            if (o instanceof PEMKeyPair kp) return conv.getKeyPair(kp).getPrivate();
            if (o instanceof PrivateKeyInfo pk) return conv.getPrivateKey(pk);
            throw new IllegalArgumentException("Not a private key PEM");
        }
    }
    public static String writeX509(X509Certificate cert) throws Exception {
        var sw = new StringWriter();
        try (var pw = new JcaPEMWriter(sw)) { pw.writeObject(cert); }
        return sw.toString();
    }
}
