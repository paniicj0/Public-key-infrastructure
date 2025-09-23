package com.info_security.is.service;
import com.info_security.is.crypto.CryptoUtil;
import com.info_security.is.crypto.PemUtil;
import com.info_security.is.dto.DnBuilder;
import com.info_security.is.dto.EeRequest;
import com.info_security.is.dto.RootRequest;
import com.info_security.is.enums.RevocationReason;
import com.info_security.is.repository.CertificateRepository;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x500.X500Name;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.*;

import static com.info_security.is.enums.CertifaceteType.EE;
import static com.info_security.is.enums.CertifaceteType.ROOT;

@Service
public class PkiService {

    private final CertificateRepository repo;
    private final CryptoUtil crypto;

    public PkiService(CertificateRepository repo, CryptoUtil crypto) {
        this.repo = repo;
        this.crypto = crypto;
        // osiguraj BC providera
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }

    /* ===================== PUBLIC API (radi sa tvojim DTO-ovima) ===================== */

    @Transactional
    public com.info_security.is.model.Certificate generateRoot(RootRequest req) throws Exception {
        int keySize = Optional.ofNullable(req.getKeySize()).orElse(4096);
        KeyPair kp = generateKeypair("RSA", keySize);

        X500Name subject = new X500Name(DnBuilder.toDn(req.getSubject()));
        Date nb = new Date();
        Date na = dateAfterDays(req.getValidityDays());

        X509Certificate cert = createSelfSignedRoot(kp, subject, nb, na);

        com.info_security.is.model.Certificate e = new com.info_security.is.model.Certificate();
        e.setType(ROOT);
        e.setSerialNumber(cert.getSerialNumber().toString());
        e.setCertificatePem(PemUtil.certToPem(cert));
        e.setPrivateKeyEnc(crypto.encryptPrivateKey(kp.getPrivate()));
        e.setNotBefore(toLdt(cert.getNotBefore()));
        e.setNotAfter(toLdt(cert.getNotAfter()));
        e.setIssuer(null);

        return repo.save(e);
    }

    @Transactional
    public com.info_security.is.model.Certificate issueEndEntity(EeRequest req) throws Exception {
        com.info_security.is.model.Certificate issuerE = repo.findById(req.getIssuerId())
                .orElseThrow(() -> new IllegalArgumentException("Issuer not found: " + req.getIssuerId()));

        // 1) Validacija izdavaoca: ne povučen, ne istekao, i da je CA (BasicConstraints true)
        if (issuerE.isRevoked()) throw new IllegalStateException("Issuer is revoked");
        if (issuerE.getNotAfter().isBefore(LocalDateTime.now())) throw new IllegalStateException("Issuer expired");
        X509Certificate issuerCert = PemUtil.pemToCert(issuerE.getCertificatePem());
        if (!isCa(issuerCert)) throw new IllegalStateException("Issuer is not a CA certificate");

        // 2) Validnost EE ne sme preći važenje izdavaoca
        int days = req.getValidityDays();
        Date nb = new Date();
        Date na = dateAfterDays(days);
        if (na.toInstant().isAfter(issuerCert.getNotAfter().toInstant())) {
            // Skrati na maksimalno dozvoljeno
            na = issuerCert.getNotAfter();
        }

        // 3) Generiši par ključeva za EE
        int keySize = Optional.ofNullable(req.getKeySize()).orElse(2048);
        KeyPair eeKeys = generateKeypair("RSA", keySize);

        X500Name subject = new X500Name(DnBuilder.toDn(req.getSubject()));
        PrivateKey issuerKey = crypto.decryptPrivateKey(issuerE.getPrivateKeyEnc());

        X509Certificate eeCert = signEndEntity(eeKeys, subject, issuerCert, issuerKey, nb, na);

        com.info_security.is.model.Certificate e = new com.info_security.is.model.Certificate();
        e.setType(EE);
        e.setSerialNumber(eeCert.getSerialNumber().toString());
        e.setCertificatePem(PemUtil.certToPem(eeCert));
        e.setPrivateKeyEnc(crypto.encryptPrivateKey(eeKeys.getPrivate()));
        e.setNotBefore(toLdt(eeCert.getNotBefore()));
        e.setNotAfter(toLdt(eeCert.getNotAfter()));
        e.setIssuer(issuerE);

        com.info_security.is.model.Certificate saved = repo.save(e);

        return saved;
    }

    @Transactional(readOnly = true)
    public byte[] generatePkcs12(Long certId, String password) throws Exception {
        com.info_security.is.model.Certificate e = repo.findById(certId)
                .orElseThrow(() -> new IllegalArgumentException("Certificate not found"));

        // 1) Napravi chain: [subject, issuer, issuer_of_issuer, ...] do ROOT
        List<X509Certificate> chain = buildChain(e);

        // 2) Učitaj privatni ključ (ako postoji; za ROOT/EE imamo ga; za neke CA možeš zabraniti download)
        PrivateKey pk = null;
        if (e.getPrivateKeyEnc() != null) {
            pk = crypto.decryptPrivateKey(e.getPrivateKeyEnc());
        }

        // 3) Spakuj u PKCS12
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);

        Certificate[] arr = chain.toArray(new Certificate[0]);
        if (pk != null) {
            ks.setKeyEntry("key", pk, password.toCharArray(), arr);
        } else {
            // bez privatnog ključa — retko ima smisla, ali dozvoljeno
            for (int i = 0; i < arr.length; i++) {
                ks.setCertificateEntry("cert-" + i, arr[i]);
            }
        }

        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            ks.store(baos, password.toCharArray());
            return baos.toByteArray();
        }
    }

    /* ===================== CORE (izdavanje) ===================== */

    private X509Certificate createSelfSignedRoot(KeyPair kp, X500Name subject, Date nb, Date na) throws Exception {
        BigInteger serial = new BigInteger(64, new SecureRandom());

        var spki = SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded());
        var v3 = new X509v3CertificateBuilder(subject, serial, nb, na, subject, spki);

        // Ekstenzije: CA:true, KeyUsage, SKI, AKI
        var extUtils = new JcaX509ExtensionUtils();
        SubjectKeyIdentifier ski = extUtils.createSubjectKeyIdentifier(kp.getPublic());
        AuthorityKeyIdentifier aki = extUtils.createAuthorityKeyIdentifier(kp.getPublic());

        v3.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        v3.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        v3.addExtension(Extension.subjectKeyIdentifier, false, ski);
        v3.addExtension(Extension.authorityKeyIdentifier, false, aki);

        var signer = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());
        X509CertificateHolder holder = v3.build(signer);

        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);
    }

    private X509Certificate signEndEntity(
            KeyPair subjectKeys, X500Name subject,
            X509Certificate issuerCert, PrivateKey issuerKey,
            Date nb, Date na) throws Exception {

        BigInteger serial = new BigInteger(64, new SecureRandom());

        var spki = SubjectPublicKeyInfo.getInstance(subjectKeys.getPublic().getEncoded());
        var issuerX500 = new X500Name(issuerCert.getSubjectX500Principal().getName());
        var v3 = new X509v3CertificateBuilder(issuerX500, serial, nb, na, subject, spki);

        var extUtils = new JcaX509ExtensionUtils();
        SubjectKeyIdentifier ski = extUtils.createSubjectKeyIdentifier(subjectKeys.getPublic());
        AuthorityKeyIdentifier aki = extUtils.createAuthorityKeyIdentifier(issuerCert.getPublicKey());

        // EE: BasicConstraints false; KeyUsage za TLS: digitalSignature + keyEncipherment
        v3.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        v3.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
        v3.addExtension(Extension.subjectKeyIdentifier, false, ski);
        v3.addExtension(Extension.authorityKeyIdentifier, false, aki);

        var signer = new JcaContentSignerBuilder("SHA256withRSA").build(issuerKey);
        X509CertificateHolder holder = v3.build(signer);

        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);
    }

    /* ===================== UTIL ===================== */

    private KeyPair generateKeypair(String algo, int size) throws Exception {
        if ("EC".equalsIgnoreCase(algo)) {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec("secp256r1")); // primer
            return kpg.generateKeyPair();
        } else {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(size);
            return kpg.generateKeyPair();
        }
    }

    private Date dateAfterDays(int days) {
        return Date.from(LocalDate.now().plusDays(days).atStartOfDay(ZoneId.systemDefault()).toInstant());
    }

    private LocalDateTime toLdt(Date d) {
        return LocalDateTime.ofInstant(d.toInstant(), ZoneId.systemDefault());
    }

    private boolean isCa(X509Certificate cert) {
        try {
            byte[] ext = cert.getExtensionValue(Extension.basicConstraints.getId());
            // Jednostavnije: Java API ima getBasicConstraints: >=0 znači CA
            return cert.getBasicConstraints() >= 0;
        } catch (Exception e) {
            return false;
        }
    }

    private List<X509Certificate> buildChain(com.info_security.is.model.Certificate leaf) throws Exception {
        List<X509Certificate> out = new ArrayList<>();
        com.info_security.is.model.Certificate cur = leaf;
        while (cur != null) {
            out.add(PemUtil.pemToCert(cur.getCertificatePem()));
            cur = cur.getIssuer();
        }
        return out.toArray(new X509Certificate[0]).length == 0 ? List.of() : out;
    }

    @Transactional
    public com.info_security.is.model.Certificate revoke(Long certId, RevocationReason reason, Long actorUserId) {
        com.info_security.is.model.Certificate e = repo.findById(certId)
                .orElseThrow(() -> new IllegalArgumentException("Certificate not found"));

        if (e.isRevoked()) return e;

        e.setRevoked(true);
        e.setRevocationReason(reason);
        e.setRevokedAt(LocalDateTime.now());
        e.setRevokedByUserId(actorUserId);
        return repo.save(e);
    }

}
