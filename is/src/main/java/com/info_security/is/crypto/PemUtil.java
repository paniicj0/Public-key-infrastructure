package com.info_security.is.crypto;

import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;

import java.io.*;
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
}
