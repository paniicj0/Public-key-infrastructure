package com.info_security.is.crypto;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.springframework.stereotype.Component;

import java.io.StringReader;

@Component
public class CsrUtil {

    public PKCS10CertificationRequest parseCsrPem(String pem) throws Exception {
        try (var sr = new StringReader(pem);
             var pemParser = new PEMParser(sr)) {
            Object obj = pemParser.readObject();
            if (!(obj instanceof PKCS10CertificationRequest csr)) {
                throw new IllegalArgumentException("Invalid CSR (expecting PKCS#10 PEM)");
            }
            var pub = new JcaPEMKeyConverter().setProvider("BC")
                    .getPublicKey(csr.getSubjectPublicKeyInfo());
            boolean ok = csr.isSignatureValid(
                    new JcaContentVerifierProviderBuilder().setProvider("BC").build(pub));
            if (!ok) throw new IllegalArgumentException("CSR signature invalid");
            return csr;
        }
    }

    public static X500Name x500(String cn, String o, String ou, String c, String email) {
        var b = new X500NameBuilder(BCStyle.INSTANCE);
        if (cn != null && !cn.isBlank()) b.addRDN(BCStyle.CN, cn);
        if (o  != null && !o.isBlank())  b.addRDN(BCStyle.O,  o);
        if (ou != null && !ou.isBlank()) b.addRDN(BCStyle.OU, ou);
        if (c  != null && !c.isBlank())  b.addRDN(BCStyle.C,  c);
        if (email != null && !email.isBlank()) b.addRDN(BCStyle.EmailAddress, email);
        return b.build();
    }

    public boolean verifyCsrSignature(PKCS10CertificationRequest csr) throws Exception {
        var verifier = new org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder()
                .setProvider("BC")
                .build(new JcaPEMKeyConverter().getPublicKey(csr.getSubjectPublicKeyInfo()));
        return csr.isSignatureValid(verifier);
    }

}
