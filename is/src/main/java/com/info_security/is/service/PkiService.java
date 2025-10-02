package com.info_security.is.service;
import com.info_security.is.crypto.CsrUtil;
import com.info_security.is.crypto.Keystores;
import com.info_security.is.dto.*;
import com.info_security.is.enums.CertifaceteType;
import com.info_security.is.enums.RevocationReason;
import com.info_security.is.enums.UserRole;
import com.info_security.is.model.CertificateModel;
import com.info_security.is.crypto.CryptoUtil;
import com.info_security.is.crypto.PemUtil;
import com.info_security.is.model.CertificateTemplate;
import com.info_security.is.model.User;
import com.info_security.is.repository.CertificateRepository;
import com.info_security.is.repository.CertificateTemplateRepository;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.asn1.x500.X500Name;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
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

    private final CsrUtil csrUtil;
    private final CertificateTemplateRepository templateRepo;


    @Autowired
    private UserService userService;


    public PkiService(CertificateRepository repo, CryptoUtil crypto, CsrUtil csrUtil, CertificateTemplateRepository templateRepo) {
        this.repo = repo;
        this.crypto = crypto;
        this.csrUtil = csrUtil;
        // osiguraj BC providera
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
        this.templateRepo = templateRepo;
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

        if (req.getTemplateId() != null) {
            var tpl = loadTemplateOrThrow(req.getTemplateId());
            ensureTemplateIssuerCompatible(tpl, issuerE); // strože pravilo (po želji)
            validateAgainstTemplate(tpl, req.getSubject(), req.getExtensions(), req.getValidityDays());
            applyTemplateDefaultsToExtensions(tpl, req.getExtensions());
        }

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

        if (req.getTemplateId() != null) {
            var tpl = loadTemplateOrThrow(req.getTemplateId());
            ensureTemplateIssuerCompatible(tpl, issuerE); // strože pravilo (po želji)
            validateAgainstTemplate(tpl, req.getSubject(), req.getExtensions(), req.getValidityDays());
            applyTemplateDefaultsToExtensions(tpl, req.getExtensions());
        }

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

    // ------------------------ REVOCATION -------------------------------------------------
    // REVOKE – core pravila:
    // ADMIN: može sve
    // CA: sme u svom lancu (po organizaciji); uprošćeno – dozvoli ako je O=org korisnika u subject ili jednom od predaka
    // USER (običan): sme samo svoje EE
    @Transactional
    public CertificateModel revoke(Long certId, RevocationReason reason) {
        User actor = userService.getCurrentUser();
        if (actor == null) throw new SecurityException("User not authenticated");

        CertificateModel cert = repo.findById(certId)
                .orElseThrow(() -> new IllegalArgumentException("Certificate not found"));

        if (Boolean.TRUE.equals(cert.isRevoked())) {
            return cert; // idempotentno
        }

        // dozvole
        if (!canRevoke(actor, cert)) {
            throw new AccessDeniedException("You are not allowed to revoke this certificate");
        }

         if (cert.getType() == CertifaceteType.CA && repo.existsByIssuerIdAndRevokedFalse(cert.getId())) {
             throw new IllegalStateException("CA certificate has active descendants; revoke them first.");
         }

        cert.setRevoked(true);
        cert.setRevocationReason(reason != null ? reason : RevocationReason.UNSPECIFIED);
        cert.setRevokedAt(LocalDateTime.now());
        cert.setRevokedByUserId(actor.getId());

        return repo.save(cert);
    }

    /** Pravila pristupa za revoke */
    private boolean canRevoke(User actor, CertificateModel target) {
        // ADMIN može sve
        if (actor.getRole() == UserRole.ADMIN) return true;

        // Običan korisnik: može samo svoje EE (pretpostavka da imaš vezu user <-> EE; ako nemaš, upotrebi email iz subject-a)
        if (actor.getRole() == UserRole.USER) {
            return target.getType() == CertifaceteType.EE
                    && eeBelongsToUserNew(actor, target); // ✅ već postoji helper
        }

        // CA korisnik: dozvoljeno u okviru svog lanca/organizacije
        if (actor.getRole() == UserRole.CA) {
            String org = userService.getCurrentUserOrganization();
            return isInUsersOrgChain(org, target);
        }

        return false;
    }

    /** Provera da li EE "pripada" korisniku – prilagodi tvojoj šemi (npr. preko ownerUserId, email-a iz subjecta, itd.) */
    private boolean eeBelongsToUser(User user, CertificateModel ee) {
        if (ee.getType() != CertifaceteType.EE) return false;
        try {
            X509Certificate c = PemUtil.pemToCert(ee.getCertificatePem());
            String subj = c.getSubjectX500Principal().getName(); // e.g. "CN=..., E=...,..."
            return subj.contains("E=" + user.getEmail());
        } catch (Exception e) {
            return false;
        }
    }

    private boolean isInUsersOrgChain(String org, CertificateModel node) {
        try {
            CertificateModel cur = node;
            while (cur != null) {
                X509Certificate cert = PemUtil.pemToCert(cur.getCertificatePem());
                String subj = cert.getSubjectX500Principal().getName();
                // gruba provera na osnovu DN; po potrebi zameni pravim X500 parserom
                if (subj.contains("O=" + org)) return true;
                cur = cur.getIssuer();
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

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

    // Provera da li je samo potpisan
    private boolean isSelfSigned(X509Certificate cert) {
        try {
            cert.verify(cert.getPublicKey());
            return cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal());
        } catch (Exception e) {
            return false;
        }
    }

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

        java.security.cert.CertPathValidator.getInstance("PKIX").validate(cp, params);
    }

    public List<CertificateResponse> listCertificates() {
        return repo.findAllByOrderByIdDesc()
                .stream().map(CertificateResponse::new).toList();
    }

    // CA moze da ima uvid samo u svoje sertifikate
    // CA može da vidi sve sertifikate koji pripadaju njegovom lancu / organizaciji
    public List<CertificateResponse> listCertificatesCA() {
        User me = userService.getCurrentUser();
        if (me == null) throw new SecurityException("User not authenticated");
        if (me.getRole() != UserRole.CA && me.getRole() != UserRole.ADMIN) {
            throw new AccessDeniedException("Only CA/ADMIN can access this list");
        }

        String org = userService.getCurrentUserOrganization(); // npr. "MyOrg"
        return repo.findAllByOrderByIdDesc().stream()
                .filter(c -> belongsToOrgChain(c, org))   // ✅ već imaš helper
                .map(CertificateResponse::new)
                .toList();
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

    // === 4.1. Izdavanje iz CSR ===
    @Transactional
    public Long issueFromCsr(Long issuerId, int validityDays, String csrPem) throws Exception {
        var ca = repo.findById(issuerId)
                .orElseThrow(() -> new IllegalArgumentException("Issuer not found"));
        var caCert = PemUtil.readX509(ca.getCertificatePem());

        if (caCert.getBasicConstraints() < 0) {
            throw new IllegalArgumentException("Selected issuer is not a CA");
        }
        var now = new Date();
        if (caCert.getNotAfter().before(now)) throw new IllegalArgumentException("CA expired");

        // 1) Parsiraj CSR i verifikuj ga
        var csr = csrUtil.parseCsrPem(csrPem);                 // PKCS10CertificationRequest
        if (!csrUtil.verifyCsrSignature(csr)) {
            throw new IllegalArgumentException("CSR signature invalid");
        }

        // 2) Ako je CA korisnik, enforce-uj organizaciju (O) iz CSR-a
        var current = userService.getCurrentUser();
        if (current == null) throw new SecurityException("User not authenticated");

        var csrOrg = getRdnString(csr.getSubject(), BCStyle.O); // npr. "MyOrg"
        if ("CA".equalsIgnoreCase(current.getRole().name())) {
            var userOrg = current.getOrganization() != null ? current.getOrganization().getName() : null;
            if (userOrg == null || csrOrg == null || !userOrg.equals(csrOrg)) {
                throw new org.springframework.web.server.ResponseStatusException(
                        org.springframework.http.HttpStatus.FORBIDDEN,
                        "CA može izdavati samo za svoju organizaciju (CSR O=" + csrOrg + ", očekivano O=" + userOrg + ")"
                );
            }
        }

        // 3) Validnost EE ne sme preći važenje CA
        var eeNotBefore = now;
        var eeNotAfter  = new Date(now.getTime() + (long)validityDays * 86_400_000L);
        if (eeNotAfter.after(caCert.getNotAfter())) {
            eeNotAfter = caCert.getNotAfter();
        }

        // 4) Potpiši EE iz CSR-a CA ključem
        var caKey = crypto.decryptPrivateKey(ca.getPrivateKeyEnc());  // ⬅⬅⬅ ovo je ključno!
        var ee = buildAndSignEEFromCsr(csr, caCert, caKey, eeNotBefore, eeNotAfter);

        // 5) Upis u bazu (CSR režim -> ne čuvamo privatni ključ)
        var entity = new CertificateModel();
        entity.setType(CertifaceteType.EE);
        entity.setIssuer(ca);
        entity.setCertificatePem(PemUtil.writeX509(ee));
        entity.setNotBefore(toLocalDateTime(ee.getNotBefore()));
        entity.setNotAfter(toLocalDateTime(ee.getNotAfter()));
        entity.setSerialNumber(ee.getSerialNumber().toString(16));
        entity.setPrivateKeyEnc(null); // CSR varijanta – privatni ključ ostaje kod korisnika

        repo.save(entity);
        return entity.getId();
    }

    public String getRdnString(X500Name subject, ASN1ObjectIdentifier oid) {
        RDN[] rdns = subject.getRDNs(oid);
        if (rdns != null && rdns.length > 0) {
            return IETFUtils.valueToString(rdns[0].getFirst().getValue());
        }
        return null;
    }

    private static LocalDateTime toLocalDateTime(Date date) {
        return date.toInstant()
                .atZone(ZoneId.systemDefault())
                .toLocalDateTime();
    }

    @Transactional
    public IssuedAutogenResult issueAutogen(Long issuerId, int validityDays, int keySize, SubjectDtoRecord subj,
                                            boolean returnP12, String p12Password) throws Exception {
        var ca = repo.findCAById(issuerId)
                .orElseThrow(() -> new IllegalArgumentException("CA not found"));
        var caCert = PemUtil.readX509(ca.getCertificatePem());
        //var caKey  = PemUtil.readPrivateKey(ca.getPrivateKeyEnc()); // dekripcija ako treba
        var caKey  = crypto.decryptPrivateKey(ca.getPrivateKeyEnc());

        if (!ca.isCa()) throw new IllegalArgumentException("Selected issuer is not a CA");
        var now = new Date();
        var eeNotBefore = now;
        var eeNotAfter  = new Date(now.getTime() + validityDays * 86_400_000L);
        if (eeNotAfter.after(caCert.getNotAfter()))
            throw new IllegalArgumentException("EE validity exceeds CA validity");

        var kp = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        var subject = CsrUtil.x500(subj.commonName(), subj.organization(), subj.orgUnit(), subj.country(), subj.email());

        var ee = buildAndSignEE(subject, kp.getPublic(), caCert, caKey, eeNotBefore, eeNotAfter);

        // persist (bez privatnog ključa)
        var entity = new CertificateModel();
        entity.setType(CertifaceteType.EE);
        entity.setIssuer(ca);
        entity.setCertificatePem(PemUtil.writeX509(ee));
        entity.setNotBefore(toLocalDateTime(ee.getNotBefore()));
        entity.setNotAfter(toLocalDateTime(ee.getNotAfter()));
        entity.setSerialNumber(ee.getSerialNumber().toString(16));
        entity.setPrivateKeyEnc(null); // NE čuvamo privatni ključ
        repo.save(entity);

        byte[] p12 = null;
        if (returnP12) {
            if (p12Password == null || p12Password.isBlank())
                throw new IllegalArgumentException("p12 password required");
            p12 = Keystores.toPkcs12(ee, kp.getPrivate(), new X509Certificate[]{ee, caCert}, p12Password.toCharArray());
        }

        return new IssuedAutogenResult(entity.getId(), p12);
    }


    private X509Certificate buildAndSignEEFromCsr(
            PKCS10CertificationRequest csr,
            X509Certificate issuerCert, PrivateKey issuerKey,
            Date notBefore, Date notAfter) throws Exception {

        var serial   = new BigInteger(160, SecureRandom.getInstanceStrong()).abs();
        var subjX500 = csr.getSubject(); // <-- X500Name iz CSR-a

        var builder = new JcaX509v3CertificateBuilder(
                issuerCert,                      // OK je ostaviti ovu overload varijantu
                serial, notBefore, notAfter,
                subjX500,                        // <-- NEMA X500Principal, već X500Name
                new JcaPEMKeyConverter().getPublicKey(csr.getSubjectPublicKeyInfo())
        );

        addEeExtensions(builder, csr);

        var signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC").build(issuerKey);
        var holder = builder.build(signer);
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);
    }

    private X509Certificate buildAndSignEE(
            X500Name subject, PublicKey eePub,
            X509Certificate issuerCert, PrivateKey issuerKey,
            Date notBefore, Date notAfter) throws Exception {

        var serial = new BigInteger(160, SecureRandom.getInstanceStrong()).abs();

        var builder = new JcaX509v3CertificateBuilder(
                issuerCert,
                serial, notBefore, notAfter,
                subject,
                eePub
        );

        addEeExtensions(builder, null);

        var signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC").build(issuerKey);
        var holder = builder.build(signer);
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);
    }

    private void addEeExtensions(JcaX509v3CertificateBuilder b, PKCS10CertificationRequest csr) throws Exception {
        // BasicConstraints: CA=false
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        // KeyUsage: digitalSignature | keyEncipherment
        b.addExtension(Extension.keyUsage, true, new KeyUsage(
                KeyUsage.digitalSignature | KeyUsage.keyEncipherment
        ));
        if (csr != null) {
            var attrs = csr.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
            if (attrs != null && attrs.length > 0) {
                var exts = Extensions.getInstance(attrs[0].getAttrValues().getObjectAt(0));
                var san = exts.getExtension(Extension.subjectAlternativeName);
                if (san != null) {
                    b.addExtension(Extension.subjectAlternativeName, san.isCritical(), san.getParsedValue());
                }

            }
        }
    }

    public record IssuedAutogenResult(Long id, byte[] p12Bytes) {}

    @Transactional(readOnly = true)
    public byte[] packPkcs12ForCsrIssued(Long certId, String privateKeyPem, String p12Password) throws Exception {
        if (p12Password == null || p12Password.isBlank()) {
            throw new IllegalArgumentException("p12 password required");
        }
        // 1) uzmi EE iz baze
        CertificateModel e = repo.findById(certId)
                .orElseThrow(() -> new IllegalArgumentException("Certificate not found"));

        // 2) izgradi lanac (EE -> ... -> ROOT)
        var chain = buildChain(e).toArray(new java.security.cert.X509Certificate[0]);

        // 3) privatni ključ iz PEM-a (ne čuvamo u bazi!)
        PrivateKey pk = PemUtil.readPrivateKey(privateKeyPem);
        assertKeyMatchesLeaf(pk, chain[0]); // sigurnosna provera

        // 4) spakuj .p12 (alias "key")
        return Keystores.toPkcs12(chain[0], pk, chain, p12Password.toCharArray());
    }

    @Transactional(readOnly = true)
    public List<CertificateResponse> listEligibleIssuersForCurrentUser() {
        var now = LocalDateTime.now();
        var me = userService.getCurrentUser();
        if (me == null) throw new SecurityException("User not authenticated");

        // 1) uzmi sve CA koji su validni i nisu povučeni
        var all = repo.findAllByOrderByIdDesc().stream()
                .filter(c -> c.getType() == CertifaceteType.CA)
                .filter(c -> !Boolean.TRUE.equals(c.isRevoked()))
                .filter(c -> (c.getNotBefore() == null || !c.getNotBefore().isAfter(now))
                        && (c.getNotAfter()  == null || !c.getNotAfter().isBefore(now)))
                .toList();

        // 2) filtriraj po ulozi
        if (me.getRole() == UserRole.ADMIN) {
            return all.stream().map(CertificateResponse::new).toList();
        }
        if (me.getRole() == UserRole.CA) {
            String org = userService.getCurrentUserOrganization();
            return all.stream().filter(ca -> {
                try {
                    var cert = PemUtil.pemToCert(ca.getCertificatePem());
                    var subj = cert.getSubjectX500Principal().getName();
                    return subj.contains("O=" + org);
                } catch (Exception e) { return false; }
            }).map(CertificateResponse::new).toList();
        }
        // USER → dozvoli sve javne CA (ili, ako hoćeš strože, filtriraj po nekom kriterijumu)
        return all.stream().map(CertificateResponse::new).toList();
    }

    @Transactional(readOnly = true)
    public List<CertificateResponse> listMyCertificates() {
        User me = userService.getCurrentUser();
        if (me == null) throw new SecurityException("User not authenticated");

        var all = repo.findAllByOrderByIdDesc();

        // CA → u svom lancu / organizaciji
        if (me.getRole() == UserRole.CA) {
            String org = userService.getCurrentUserOrganization();
            return all.stream()
                    .filter(c -> belongsToOrgChain(c, org))   // ⬅⬅⬅ promenjen filter
                    .map(CertificateResponse::new)
                    .toList();
        }


        // USER → njegovi EE po email-u iz subject/SAN
        return repo.findAllByOrderByIdDesc().stream()
                .filter(c -> c.getType() == CertifaceteType.EE && eeBelongsToUserNew(me, c))
                .map(CertificateResponse::new)
                .toList();

    }

    // robustno: prolazi uzlazno kroz chain: node -> issuer -> issuer...
    private boolean belongsToOrgChain(CertificateModel node, String org) {
        if (org == null || org.isBlank()) return false;
        String wanted = org.trim().toLowerCase(java.util.Locale.ROOT);
        try {
            CertificateModel cur = node;
            while (cur != null) {
                X509Certificate cert = PemUtil.pemToCert(cur.getCertificatePem());
                var x5 = new org.bouncycastle.cert.jcajce.JcaX509CertificateHolder(cert).getSubject();
                String o = getRdnStringNew(x5, BCStyle.O);
                if (o != null && o.trim().toLowerCase(java.util.Locale.ROOT).equals(wanted)) {
                    return true;
                }
                cur = cur.getIssuer();
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean eeBelongsToUserNew(User user, CertificateModel ee) {
        if (ee.getType() != CertifaceteType.EE) return false;
        try {
            X509Certificate cert = PemUtil.pemToCert(ee.getCertificatePem());
            String userMail = safeLower(user.getEmail());
            String certMail = safeLower(extractEmailRobust(cert));
            return certMail != null && certMail.equals(userMail);
        } catch (Exception e) {
            return false;
        }
    }

    private String extractEmailRobust(X509Certificate cert) throws Exception {
        X500Name x500 = new JcaX509CertificateHolder(cert).getSubject();
        String dnEmail = getRdnStringNew(x500, BCStyle.EmailAddress); // OID za email
        if (dnEmail != null && !dnEmail.isBlank()) return dnEmail;

        var sans = cert.getSubjectAlternativeNames();
        if (sans != null) {
            for (var san : sans) {
                Integer type = (Integer) san.get(0);
                if (type != null && type == 1) {
                    return String.valueOf(san.get(1));
                }
            }
        }
        return null;
    }

    private String getRdnStringNew(org.bouncycastle.asn1.x500.X500Name subject,
                                   org.bouncycastle.asn1.ASN1ObjectIdentifier oid) {
        var rdns = subject.getRDNs(oid);
        if (rdns != null && rdns.length > 0) {
            return org.bouncycastle.asn1.x500.style.IETFUtils.valueToString(
                    rdns[0].getFirst().getValue());
        }
        return null;
    }

    private String safeLower(String s) {
        return s == null ? null : s.trim().toLowerCase(java.util.Locale.ROOT);
    }


    // ===== Template helpers =====
    private CertificateTemplate loadTemplateOrThrow(Long templateId) {
        return templateRepo.findById(templateId)
                .orElseThrow(() -> new IllegalArgumentException("Template not found: " + templateId));
    }

    /** Ako hoćeš strože: zahtevaj da template.issuer.id == req.issuerId */
    private void ensureTemplateIssuerCompatible(CertificateTemplate tpl, CertificateModel issuer) {
        if (tpl.getIssuer() == null) return;
        if (!Objects.equals(tpl.getIssuer().getId(), issuer.getId())) {
            throw new IllegalArgumentException("Selected issuer does not match template issuer.");
        }
    }

    /** CN/SAN regex + TTL: subject.commonName i extensions.subjectAltNames */
    private void validateAgainstTemplate(CertificateTemplate tpl,
                                         SubjectDto subj,
                                         ExtensionsDto ext,
                                         int requestedDays) {
        // CN
        if (tpl.getCnRegex() != null && subj != null && subj.commonName != null) {
            if (!subj.commonName.matches(tpl.getCnRegex())) {
                throw new IllegalArgumentException("CN does not match template regex.");
            }
        }
        // SAN
        if (tpl.getSanRegex() != null && ext != null && ext.subjectAltNames != null) {
            java.util.regex.Pattern p = java.util.regex.Pattern.compile(tpl.getSanRegex());
            for (String san : ext.subjectAltNames) {
                String value = san;
                // Dozvoli formate "DNS:example.com" / "IP:1.2.3.4"
                if (san.startsWith("DNS:")) value = san.substring(4);
                else if (san.startsWith("IP:")) value = san.substring(3);
                if (!p.matcher(value).matches()) {
                    throw new IllegalArgumentException("SAN '" + san + "' does not match template regex.");
                }
            }
        }
        // TTL
        if (requestedDays > tpl.getTtlDays()) {
            throw new IllegalArgumentException("Requested validity exceeds template TTL.");
        }
    }

    /** Merge default KeyUsage/EKU iz template-a u tvoj ExtensionsDto */
    private void applyTemplateDefaultsToExtensions(CertificateTemplate tpl, ExtensionsDto ext) {
        if (ext == null) return;

        // KeyUsage: tvoj ExtensionsDto koristi booleane. Mapiramo iz enum/string vrednosti šablona.
        // Pretpostavka: u template-u su KU nazivi: DIGITAL_SIGNATURE, KEY_ENCIPHERMENT, DATA_ENCIPHERMENT, KEY_AGREEMENT, KEY_CERT_SIGN, CRL_SIGN ...
        if (tpl.getKeyUsage() != null) {
            var names = tpl.getKeyUsage().stream().map(Enum::name).toList();
            if (names.contains("DIGITAL_SIGNATURE")) ext.digitalSignature = true;
            if (names.contains("KEY_ENCIPHERMENT"))  ext.keyEncipherment = true;
            if (names.contains("DATA_ENCIPHERMENT")) ext.dataEncipherment = true;
            if (names.contains("KEY_AGREEMENT"))     ext.keyAgreement = true;

        }

        // ExtendedKeyUsage: u ExtensionsDto imaš List<String> (serverAuth, clientAuth, codeSigning...)
        if (tpl.getExtendedKeyUsage() != null && !tpl.getExtendedKeyUsage().isEmpty()) {
            if (ext.extendedKeyUsage == null) ext.extendedKeyUsage = new ArrayList<>();
            for (var eku : tpl.getExtendedKeyUsage()) {
                var name = eku.name(); // npr. SERVER_AUTH
                // mapiramo na tvoja imena koja koristiš u switch-u (serverAuth, clientAuth, codeSigning)
                switch (name) {
                    case "SERVER_AUTH" -> addIfAbsent(ext.extendedKeyUsage, "serverAuth");
                    case "CLIENT_AUTH" -> addIfAbsent(ext.extendedKeyUsage, "clientAuth");
                    case "CODE_SIGNING" -> addIfAbsent(ext.extendedKeyUsage, "codeSigning");
                    case "EMAIL_PROTECTION" -> addIfAbsent(ext.extendedKeyUsage, "emailProtection");
                    case "TIME_STAMPING" -> addIfAbsent(ext.extendedKeyUsage, "timeStamping");
                    case "OCSP_SIGNING" -> addIfAbsent(ext.extendedKeyUsage, "OCSPSigning");
                    case "ANY_EXTENDED_USAGE" -> addIfAbsent(ext.extendedKeyUsage, "serverAuth"); // fallback
                }
            }
        }
    }
    private static void addIfAbsent(List<String> list, String val) {
        if (list.stream().noneMatch(v -> v.equalsIgnoreCase(val))) list.add(val);
    }

}
