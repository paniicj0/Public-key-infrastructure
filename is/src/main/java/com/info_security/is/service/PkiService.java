package com.info_security.is.service;
import com.info_security.is.dto.*;
import com.info_security.is.enums.CertifaceteType;
import com.info_security.is.enums.UserRole;
import com.info_security.is.model.CertificateModel;
import com.info_security.is.crypto.CryptoUtil;
import com.info_security.is.crypto.PemUtil;
import com.info_security.is.model.User;
import com.info_security.is.repository.CertificateRepository;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x500.X500Name;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.*;
import java.util.*;

import static com.info_security.is.enums.CertifaceteType.EE;
import static com.info_security.is.enums.CertifaceteType.ROOT;
import static org.bouncycastle.asn1.x500.style.BCStyle.*;

@Service
public class PkiService {

    private final CertificateRepository repo;
    private final CryptoUtil crypto;

    @Autowired
    private UserService userService;


    public PkiService(CertificateRepository repo, CryptoUtil crypto) {
        this.repo = repo;
        this.crypto = crypto;
        // osiguraj BC providera
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }

    /* ===================== PUBLIC API (radi sa tvojim DTO-ovima) ===================== */

    // CA izdavanje
    @Transactional
    public CertificateModel issueIntermediate(CaRequest req) throws Exception {
        // 1) Učitaj izdavaoca
        CertificateModel issuerE = repo.findById(req.getIssuerId())
                .orElseThrow(() -> new IllegalArgumentException("Issuer not found: " + req.getIssuerId()));

        // 2) Validacija izdavaoca (vreme, status, CA, keyCertSign)
        assertIssuerIsValid(issuerE);

        // 3) Vremenski opseg za novi CA (ne sme da pređe izdavaoca)
        X509Certificate issuerCert = PemUtil.pemToCert(issuerE.getCertificatePem());
        Date nb = new Date();
        Date na = dateAfterDays(req.getValidityDays());
        if (na.toInstant().isAfter(issuerCert.getNotAfter().toInstant())) {
            na = issuerCert.getNotAfter();
        }

        // 4) Ključevi za subject CA
        int keySize = Optional.ofNullable(req.getKeySize()).orElse(4096);
        KeyPair caKeys = generateKeypair("RSA", keySize);

        // 5) Imena i builder
        X500Name subject = buildX500(req.getSubject()).build();
        X500Name issuerName = X500Name.getInstance(issuerCert.getSubjectX500Principal().getEncoded());
        BigInteger serial = new BigInteger(160, new SecureRandom());

        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                issuerName, serial, nb, na, subject, caKeys.getPublic());

        // 6) Ekstenzije za CA (BasicConstraints + pathLen, KeyUsage, SKI/AKI)
        applyExtensionsForCA(b, caKeys.getPublic(), issuerCert, req.getExtensions());

        // 7) Potpis
        PrivateKey issuerKey = crypto.decryptPrivateKey(issuerE.getPrivateKeyEnc());
        var signer = new JcaContentSignerBuilder("SHA256withRSA").build(issuerKey);
        X509CertificateHolder holder = b.build(signer);
        X509Certificate caCert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);
        caCert.verify(issuerCert.getPublicKey()); // sanity check

        // 8) Upis u bazu
        CertificateModel e = new CertificateModel();
        e.setType(CertifaceteType.CA);
        e.setSerialNumber(caCert.getSerialNumber().toString());
        e.setCertificatePem(PemUtil.certToPem(caCert));
        e.setPrivateKeyEnc(crypto.encryptPrivateKey(caKeys.getPrivate()));
        e.setNotBefore(toLdt(caCert.getNotBefore()));
        e.setNotAfter(toLdt(caCert.getNotAfter()));
        e.setIssuer(issuerE);
        // ako tvoj model ima polje keyCertSign, ovde bi bilo: e.setKeyCertSign(true);

        return repo.save(e);
    }

    // Izdavanje root sertifikata
    @Transactional
    public CertificateModel generateRoot(RootRequest req) throws Exception {
        int keySize = Optional.ofNullable(req.getKeySize()).orElse(4096);
        KeyPair kp = generateKeypair("RSA", keySize);

        X500Name subject = buildX500(req.getSubject()).build();
        Date nb = new Date();
        Date na = dateAfterDays(req.getValidityDays());

        X509Certificate cert = createSelfSignedRoot(kp, subject, nb, na);

        CertificateModel e = new CertificateModel();
        e.setType(ROOT);
        e.setSerialNumber(cert.getSerialNumber().toString());
        e.setCertificatePem(PemUtil.certToPem(cert));
        e.setPrivateKeyEnc(crypto.encryptPrivateKey(kp.getPrivate()));
        e.setNotBefore(toLdt(cert.getNotBefore()));
        e.setNotAfter(toLdt(cert.getNotAfter()));
        e.setIssuer(null);

        return repo.save(e);
    }

    // Izdavanje EE sertifikata (potpisan CA ili Root sertifikatom)
    @Transactional
    public CertificateModel issueEndEntity(EeRequest req) throws Exception {
        CertificateModel issuerE = repo.findById(req.getIssuerId())
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

        X500Name subject = buildX500(req.getSubject()).build();
        PrivateKey issuerKey = crypto.decryptPrivateKey(issuerE.getPrivateKeyEnc());

        BigInteger serial = new BigInteger(160, new SecureRandom());
        var spki = SubjectPublicKeyInfo.getInstance(eeKeys.getPublic().getEncoded());
        var issuerX500 = X500Name.getInstance(issuerCert.getSubjectX500Principal().getEncoded());

        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                issuerX500, serial, nb, na, subject, spki);

        // Dodaj ekstenzije za EE (uključuje digitalSignature)
        applyExtensionsForEE(b, eeKeys.getPublic(), issuerCert, req.getExtensions());

        var signer = new JcaContentSignerBuilder("SHA256withRSA").build(issuerKey);
        X509CertificateHolder holder = b.build(signer);
        X509Certificate eeCert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);
        CertificateModel e = new CertificateModel();
        e.setType(EE);
        e.setSerialNumber(eeCert.getSerialNumber().toString());
        e.setCertificatePem(PemUtil.certToPem(eeCert));
        e.setPrivateKeyEnc(crypto.encryptPrivateKey(eeKeys.getPrivate()));
        e.setNotBefore(toLdt(eeCert.getNotBefore()));
        e.setNotAfter(toLdt(eeCert.getNotAfter()));
        e.setIssuer(issuerE);

        CertificateModel saved = repo.save(e);

        return saved;
    }

    //IZDAVANJE EE SERITFIKATA OD CA USERA SA PREDEFINISANOM ORGANIZACIJOM
    @Transactional
    public CertificateModel issueEndEntitycreateCAuser(EeRequest req) throws Exception {
        CertificateModel issuerE = repo.findById(req.getIssuerId())
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

        X500Name subject = buildX500WithUserOrganization(req.getSubject()).build();
        PrivateKey issuerKey = crypto.decryptPrivateKey(issuerE.getPrivateKeyEnc());

        BigInteger serial = new BigInteger(160, new SecureRandom());
        var spki = SubjectPublicKeyInfo.getInstance(eeKeys.getPublic().getEncoded());
        var issuerX500 = X500Name.getInstance(issuerCert.getSubjectX500Principal().getEncoded());

        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                issuerX500, serial, nb, na, subject, spki);

        // Dodaj ekstenzije za EE (uključuje digitalSignature)
        applyExtensionsForEE(b, eeKeys.getPublic(), issuerCert, req.getExtensions());

        var signer = new JcaContentSignerBuilder("SHA256withRSA").build(issuerKey);
        X509CertificateHolder holder = b.build(signer);
        X509Certificate eeCert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);
        CertificateModel e = new CertificateModel();
        e.setType(EE);
        e.setSerialNumber(eeCert.getSerialNumber().toString());
        e.setCertificatePem(PemUtil.certToPem(eeCert));
        e.setPrivateKeyEnc(crypto.encryptPrivateKey(eeKeys.getPrivate()));
        e.setNotBefore(toLdt(eeCert.getNotBefore()));
        e.setNotAfter(toLdt(eeCert.getNotAfter()));
        e.setIssuer(issuerE);

        CertificateModel saved = repo.save(e);

        return saved;
    }

    // Preuzimanje sertifikata u .p12
    @Transactional(readOnly = true)
    public byte[] generatePkcs12(Long certId, String password) throws Exception {
        CertificateModel e = repo.findById(certId)
                .orElseThrow(() -> new IllegalArgumentException("Certificate not found"));

        List<X509Certificate> chain = buildChain(e);

        System.out.println("=== CERT CHAIN FOR " + certId + " ===");
        for (int i = 0; i < chain.size(); i++) {
            X509Certificate c = chain.get(i);
            System.out.println("#" + i + " Subject: " + c.getSubjectX500Principal());
            System.out.println("   Issuer : " + c.getIssuerX500Principal());
            System.out.println("   Is CA  : " + (c.getBasicConstraints() >= 0));
            System.out.println("   Self?  : " + isSelfSigned(c));
            System.out.println("---");
        }

        // Provera potpisa između karika
        assertChainSignature(chain);
        assertChainPKIX(chain);


        //(workaround) – probaj bez root-a
        List<X509Certificate> forKeyEntry = chain;

        // Učitaj privatni ključ i proveri da pripada leaf-u
        PrivateKey pk = (e.getPrivateKeyEnc() != null) ? crypto.decryptPrivateKey(e.getPrivateKeyEnc()) : null;
        assertKeyMatchesLeaf(pk, forKeyEntry.get(0));

        // Spakuj u PKCS12
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);

        java.security.cert.Certificate[] arr = forKeyEntry.toArray(new java.security.cert.Certificate[0]);
        if (pk != null) {
            ks.setKeyEntry("key", pk, password.toCharArray(), arr);
        } else {
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
        BigInteger serial = new BigInteger(160, new SecureRandom());

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

        // Digitalni potpis
        var signer = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());
        X509CertificateHolder holder = v3.build(signer);

        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);
    }

    private X509Certificate signEndEntity(
            KeyPair subjectKeys, X500Name subject,
            X509Certificate issuerCert, PrivateKey issuerKey,
            Date nb, Date na) throws Exception {

        BigInteger serial = new BigInteger(160, new SecureRandom());

        var spki = SubjectPublicKeyInfo.getInstance(subjectKeys.getPublic().getEncoded());
        var issuerX500 = X500Name.getInstance(issuerCert.getSubjectX500Principal().getEncoded());
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
            return cert.getBasicConstraints() >= 0;
        } catch (Exception e) {
            return false;
        }
    }

    private List<X509Certificate> buildChain(CertificateModel leaf) throws Exception {
        List<X509Certificate> out = new ArrayList<>();
        CertificateModel cur = leaf;
        while (cur != null) {
            out.add(PemUtil.pemToCert(cur.getCertificatePem()));
            cur = cur.getIssuer();
        }
        return out; // samo to!
    }

    // TODO - REVOKE
//    @Transactional
//    public CertificateModel revoke(Long certId, RevocationReason reason, Long actorUserId) {
//        CertificateModel e = repo.findById(certId)
//                .orElseThrow(() -> new IllegalArgumentException("Certificate not found"));
//
//        if (e.isRevoked()) return e;
//
//        e.setRevoked(true);
//        e.setRevocationReason(reason);
//        e.setRevokedAt(LocalDateTime.now());
//        e.setRevokedByUserId(actorUserId);
//        return repo.save(e);
//    }

    /* ======== Helpers ======== */

    private X500NameBuilder buildX500(SubjectDto s) {
        X500NameBuilder b = new X500NameBuilder(BCStyle.INSTANCE);
        if (s.commonName != null) b.addRDN(CN, s.commonName);
        if (s.organization != null) b.addRDN(O, s.organization);
        if (s.orgUnit != null) b.addRDN(OU, s.orgUnit);
        if (s.country != null) b.addRDN(C, s.country);
        if (s.state != null) b.addRDN(ST, s.state);
        if (s.locality != null) b.addRDN(L, s.locality);
        if (s.email != null) b.addRDN(EmailAddress, s.email);
        return b;
    }

//    private Date parseStart(String iso) { return Date.from(OffsetDateTime.parse(iso).toInstant()); }
//    private Date parseEnd(String iso) { return Date.from(OffsetDateTime.parse(iso).toInstant()); }

//    private KeyPair generateKeyPair(String keyAlg, Integer keySize) throws Exception {
//        if ("EC".equalsIgnoreCase(keyAlg)) {
//            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
//            kpg.initialize(256);
//            return kpg.generateKeyPair();
//        } else {
//            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
//            kpg.initialize(keySize != null ? keySize : 3072);
//            return kpg.generateKeyPair();
//        }
//    }

//    private BigInteger randomSerial() {
//        return new BigInteger(160, new SecureRandom()).abs();
//    }


    // Da li je izdavaoc sertifikata validan
    private void assertIssuerIsValid(CertificateModel issuer) throws Exception {
        // 1) vreme
        LocalDateTime now = LocalDateTime.now();
        if (issuer.getNotBefore().isAfter(now) || issuer.getNotAfter().isBefore(now))
            throw new IllegalArgumentException("Issuer not valid at current time.");

        // 2) status
        if (issuer.isRevoked())
            throw new IllegalArgumentException("Issuer is revoked.");

        // 3) CA i keyCertSign iz samog X509 sertifikata
        X509Certificate issuerCert = PemUtil.pemToCert(issuer.getCertificatePem());

        // CA check: getBasicConstraints() >= 0 znači CA
        if (issuerCert.getBasicConstraints() < 0)
            throw new IllegalArgumentException("Issuer is not a CA certificate.");

        // keyCertSign je indeks 5 u getKeyUsage()
        boolean hasKeyCertSign = issuerCert.getKeyUsage() != null
                && issuerCert.getKeyUsage().length > 5
                && issuerCert.getKeyUsage()[5];

        if (!hasKeyCertSign)
            throw new IllegalArgumentException("Issuer lacks keyCertSign usage.");
    }

//
//    private X509Certificate toJavaCert(X509CertificateHolder holder) throws Exception {
//        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);
//    }
//
//    private String toPem(X509Certificate cert) throws Exception {
//        String b64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(cert.getEncoded());
//        return "-----BEGIN CERTIFICATE-----\n" + b64 + "\n-----END CERTIFICATE-----\n";
//    }



    // Provera da li je samo potpisan
    private boolean isSelfSigned(X509Certificate cert) {
        try {
            cert.verify(cert.getPublicKey());
            return cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal());
        } catch (Exception e) {
            return false;
        }
    }

//    private List<X509Certificate> stripRootIfPresent(List<X509Certificate> chain) {
//        if (chain.size() >= 2 && isSelfSigned(chain.get(chain.size() - 1))) {
//            return new ArrayList<>(chain.subList(0, chain.size() - 1)); // bez root-a
//        }
//        return chain;
//    }

    private void assertChainSignature(List<X509Certificate> chain) throws Exception {
        for (int i = 0; i < chain.size() - 1; i++) {
            X509Certificate child = chain.get(i);
            X509Certificate parent = chain.get(i + 1);
            child.verify(parent.getPublicKey()); // baciće exception ako link nije dobar
        }
    }
    private void assertKeyMatchesLeaf(PrivateKey pk, X509Certificate leaf) {
        if (pk == null) return;
        if (pk.getAlgorithm().equalsIgnoreCase("RSA") && leaf.getPublicKey() instanceof java.security.interfaces.RSAPublicKey pub) {
            var priv = (java.security.interfaces.RSAPrivateKey) pk;
            if (pk instanceof java.security.interfaces.RSAPrivateCrtKey crt) {
                if (!crt.getModulus().equals(pub.getModulus())) {
                    throw new IllegalStateException("Private key does not match leaf certificate public key (modulus mismatch).");
                }
            }
        }
    }

    /* ======== Ekstenzije ======== */

    private void applyExtensionsForCA(JcaX509v3CertificateBuilder b,
                                      PublicKey subjectPub,
                                      X509Certificate issuerCert,
                                      ExtensionsDto extDto) throws Exception {
        JcaX509ExtensionUtils ext = new JcaX509ExtensionUtils();
        // SKI / AKI
        b.addExtension(org.bouncycastle.asn1.x509.Extension.subjectKeyIdentifier, false,
                ext.createSubjectKeyIdentifier(subjectPub));
        if (issuerCert != null) {
            b.addExtension(org.bouncycastle.asn1.x509.Extension.authorityKeyIdentifier, false,
                    ext.createAuthorityKeyIdentifier(issuerCert));
        } else {
            b.addExtension(org.bouncycastle.asn1.x509.Extension.authorityKeyIdentifier, false,
                    ext.createAuthorityKeyIdentifier(subjectPub)); // self
        }
        // BasicConstraints CA
        org.bouncycastle.asn1.x509.BasicConstraints bc =
                (extDto != null && extDto.pathLen != null)
                        ? new org.bouncycastle.asn1.x509.BasicConstraints(extDto.pathLen) // CA + pathLen
                        : new org.bouncycastle.asn1.x509.BasicConstraints(true);          // CA bez pathLen
        b.addExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints, true, bc);
        // KeyUsage
        int usage = org.bouncycastle.asn1.x509.KeyUsage.keyCertSign | org.bouncycastle.asn1.x509.KeyUsage.cRLSign;
        b.addExtension(org.bouncycastle.asn1.x509.Extension.keyUsage, true,
                new org.bouncycastle.asn1.x509.KeyUsage(usage));
    }

    private void applyExtensionsForEE(JcaX509v3CertificateBuilder b,
                                      PublicKey subjectPub,
                                      X509Certificate issuerCert,
                                      ExtensionsDto extDto) throws Exception {
        JcaX509ExtensionUtils ext = new JcaX509ExtensionUtils();
        b.addExtension(org.bouncycastle.asn1.x509.Extension.subjectKeyIdentifier, false,
                ext.createSubjectKeyIdentifier(subjectPub));
        b.addExtension(org.bouncycastle.asn1.x509.Extension.authorityKeyIdentifier, false,
                ext.createAuthorityKeyIdentifier(issuerCert));

        // BasicConstraints: cA=false
        b.addExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints, true,
                new org.bouncycastle.asn1.x509.BasicConstraints(false));

        // KeyUsage
        int usage = 0;
        if (extDto == null || ( !extDto.digitalSignature && !extDto.keyEncipherment && !extDto.dataEncipherment && !extDto.keyAgreement )) {
            // default za TLS server
            usage = org.bouncycastle.asn1.x509.KeyUsage.digitalSignature
                    | org.bouncycastle.asn1.x509.KeyUsage.keyEncipherment;
        } else {
            if (extDto.digitalSignature)  usage |= org.bouncycastle.asn1.x509.KeyUsage.digitalSignature;
            if (extDto.keyEncipherment)   usage |= org.bouncycastle.asn1.x509.KeyUsage.keyEncipherment;
            if (extDto.dataEncipherment)  usage |= org.bouncycastle.asn1.x509.KeyUsage.dataEncipherment;
            if (extDto.keyAgreement)      usage |= org.bouncycastle.asn1.x509.KeyUsage.keyAgreement;
        }
        b.addExtension(org.bouncycastle.asn1.x509.Extension.keyUsage, true,
                new org.bouncycastle.asn1.x509.KeyUsage(usage));

        // EKU (default: serverAuth+clientAuth ako nije zadato)
        List<String> eku = (extDto != null && extDto.extendedKeyUsage != null && !extDto.extendedKeyUsage.isEmpty())
                ? extDto.extendedKeyUsage
                : List.of("serverAuth","clientAuth");
        var kpIds = eku.stream().map(s -> switch (s) {
            case "serverAuth" -> org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_serverAuth;
            case "clientAuth" -> org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_clientAuth;
            case "codeSigning" -> org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_codeSigning;
            default -> org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_serverAuth;
        }).toArray(org.bouncycastle.asn1.x509.KeyPurposeId[]::new);
        b.addExtension(org.bouncycastle.asn1.x509.Extension.extendedKeyUsage, false,
                new org.bouncycastle.asn1.x509.ExtendedKeyUsage(kpIds));

        // SAN (ako je zadat)
        if (extDto != null && extDto.subjectAltNames != null && !extDto.subjectAltNames.isEmpty()) {
            var names = extDto.subjectAltNames.stream().map(val -> {
                // Dozvoli "DNS:example.com" ili "IP:1.2.3.4"
                if (val.startsWith("DNS:")) {
                    return new org.bouncycastle.asn1.x509.GeneralName(
                            org.bouncycastle.asn1.x509.GeneralName.dNSName, val.substring(4));
                } else if (val.startsWith("IP:")) {
                    return new org.bouncycastle.asn1.x509.GeneralName(
                            org.bouncycastle.asn1.x509.GeneralName.iPAddress, val.substring(3));
                } else {
                    return new org.bouncycastle.asn1.x509.GeneralName(
                            org.bouncycastle.asn1.x509.GeneralName.dNSName, val);
                }
            }).toArray(org.bouncycastle.asn1.x509.GeneralName[]::new);
            var gns = new org.bouncycastle.asn1.x509.GeneralNames(names);
            b.addExtension(org.bouncycastle.asn1.x509.Extension.subjectAlternativeName, false, gns);
        }
    }


    private void assertChainPKIX(List<X509Certificate> chain) throws Exception {
        if (chain.size() < 2) return;

        X509Certificate root = chain.get(chain.size() - 1);

        // 1) CertPath od [EE..Intermediate] (bez root-a)
        var cf = java.security.cert.CertificateFactory.getInstance("X.509");
        var cp = cf.generateCertPath(chain.subList(0, chain.size() - 1));

        // 2) TrustAnchor iz (Subject, PublicKey) – stabilniji nego direkt iz X509
        var anchor = new java.security.cert.TrustAnchor(
                root.getSubjectX500Principal(), root.getPublicKey(), null);

        var params = new java.security.cert.PKIXParameters(java.util.Set.of(anchor));
        params.setRevocationEnabled(false);
        // (opciono) Ako koristiš BC:
        // params.setSigProvider("BC");

        java.security.cert.CertPathValidator.getInstance("PKIX").validate(cp, params);
    }

    public List<CertificateResponse> listCertificates() {
        return repo.findAllByOrderByIdDesc()
                .stream().map(CertificateResponse::new).toList();
    }

    // CA moze da ima uvid samo u svoje sertifikate
    public List<CertificateResponse> listCertificatesCA() {
        User currentUser = userService.getCurrentUser();
        if (currentUser == null) {
            throw new SecurityException("User not authenticated");
        }

        return repo.findById(currentUser.getId())
                    .stream().map(CertificateResponse::new).toList();
    }


    //AUTOMATSKI SE UNOSI ORGANIZACIJA KORISNIKA
    @Transactional
    public CertificateModel issueIntermediateCaUser(CaRequest req) throws Exception {
        // 1) Učitaj izdavaoca
        CertificateModel issuerE = repo.findById(req.getIssuerId())
                .orElseThrow(() -> new IllegalArgumentException("Issuer not found: " + req.getIssuerId()));

        // 2) Validacija izdavaoca (vreme, status, CA, keyCertSign)
        assertIssuerIsValid(issuerE);

        // 3) Vremenski opseg za novi CA (ne sme da pređe izdavaoca)
        X509Certificate issuerCert = PemUtil.pemToCert(issuerE.getCertificatePem());
        Date nb = new Date();
        Date na = dateAfterDays(req.getValidityDays());
        if (na.toInstant().isAfter(issuerCert.getNotAfter().toInstant())) {
            na = issuerCert.getNotAfter();
        }

        // 4) Ključevi za subject CA
        int keySize = Optional.ofNullable(req.getKeySize()).orElse(4096);
        KeyPair caKeys = generateKeypair("RSA", keySize);

        // 5) Imena i builder
        X500Name subject = buildX500WithUserOrganization(req.getSubject()).build();
        X500Name issuerName = X500Name.getInstance(issuerCert.getSubjectX500Principal().getEncoded());
        BigInteger serial = new BigInteger(160, new SecureRandom());

        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                issuerName, serial, nb, na, subject, caKeys.getPublic());

        // 6) Ekstenzije za CA (BasicConstraints + pathLen, KeyUsage, SKI/AKI)
        applyExtensionsForCA(b, caKeys.getPublic(), issuerCert, req.getExtensions());

        // 7) Potpis
        PrivateKey issuerKey = crypto.decryptPrivateKey(issuerE.getPrivateKeyEnc());
        var signer = new JcaContentSignerBuilder("SHA256withRSA").build(issuerKey);
        X509CertificateHolder holder = b.build(signer);
        X509Certificate caCert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);
        caCert.verify(issuerCert.getPublicKey()); // sanity check

        // 8) Upis u bazu
        CertificateModel e = new CertificateModel();
        e.setType(CertifaceteType.CA);
        e.setSerialNumber(caCert.getSerialNumber().toString());
        e.setCertificatePem(PemUtil.certToPem(caCert));
        e.setPrivateKeyEnc(crypto.encryptPrivateKey(caKeys.getPrivate()));
        e.setNotBefore(toLdt(caCert.getNotBefore()));
        e.setNotAfter(toLdt(caCert.getNotAfter()));
        e.setIssuer(issuerE);
        // ako tvoj model ima polje keyCertSign, ovde bi bilo: e.setKeyCertSign(true);

        return repo.save(e);
    }

    private X500NameBuilder buildX500WithUserOrganization(SubjectDto s) {
        X500NameBuilder b = new X500NameBuilder(BCStyle.INSTANCE);

        // Common Name (CN) - koristi iz DTO
        if (s.commonName != null) b.addRDN(CN, s.commonName);

        // Organizacija (O) - UVEK koristi organizaciju trenutnog korisnika
        String userOrganization = userService.getCurrentUserOrganization();
        b.addRDN(O, userOrganization);

        // Ostala polja - koristi iz DTO
        if (s.orgUnit != null) b.addRDN(OU, s.orgUnit);
        if (s.country != null) b.addRDN(C, s.country);
        if (s.state != null) b.addRDN(ST, s.state);
        if (s.locality != null) b.addRDN(L, s.locality);
        if (s.email != null) b.addRDN(EmailAddress, s.email);

        return b;
    }


}
