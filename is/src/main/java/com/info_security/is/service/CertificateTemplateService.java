package com.info_security.is.service;
import com.info_security.is.dto.CreateTemplateRequest;
import com.info_security.is.dto.TemplateResponse;
import com.info_security.is.dto.UpdateTemplateRequest;
import com.info_security.is.enums.TemplateEKU;
import com.info_security.is.enums.TemplateKeyUsage;
import com.info_security.is.model.CertificateModel;
import com.info_security.is.model.CertificateTemplate;
import com.info_security.is.model.User;
import com.info_security.is.repository.CertificateRepository;
import com.info_security.is.repository.CertificateTemplateRepository;
import jakarta.transaction.Transactional;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
public class CertificateTemplateService {

    private final CertificateTemplateRepository repo;
    private final CertificateRepository certRepo;

    public CertificateTemplateService(CertificateTemplateRepository repo, CertificateRepository certRepo) {
        this.repo = repo;
        this.certRepo = certRepo;
    }

    @Transactional
    public TemplateResponse create(CreateTemplateRequest req, User owner) {
        validateRegex(req.cnRegex, "CN");
        validateRegex(req.sanRegex, "SAN");
        if (req.ttlDays <= 0) throw new IllegalArgumentException("ttlDays mora biti > 0");

        CertificateModel issuer = certRepo.findById(req.issuerId)
                .orElseThrow(() -> new IllegalArgumentException("Issuer ne postoji"));

        // 1) issuer mora biti CA i važeći (nepovučen, u roku)
        ensureIssuerIsValidCA(issuer);

        // 2) opcija: ensureIssuerBelongsToOwnersChain(issuer, owner);

        if (repo.existsByNameAndOwner(req.name, owner)) {
            throw new IllegalArgumentException("Šablon sa ovim imenom već postoji");
        }

        var entity = new CertificateTemplate();
        entity.setName(req.name);
        entity.setIssuer(issuer);
        entity.setCnRegex(emptyToNull(req.cnRegex));
        entity.setSanRegex(emptyToNull(req.sanRegex));
        entity.setTtlDays(req.ttlDays);
        entity.setKeyUsage(mapKeyUsage(req.keyUsage));
        entity.setExtendedKeyUsage(mapExtKeyUsage(req.extendedKeyUsage));
        entity.setOwner(owner);
        // createdAt/updatedAt se pune @PrePersist

        repo.save(entity);
        return toResponse(entity);
    }

    public List<TemplateResponse> listMine(User owner) {
        return repo.findAllByOwnerOrderByUpdatedAtDesc(owner).stream()
                .map(this::toResponse).toList();
    }

    public TemplateResponse getMine(Long id, User owner) {
        var entity = repo.findByIdAndOwner(id, owner)
                .orElseThrow(() -> new IllegalArgumentException("Šablon nije pronađen"));
        return toResponse(entity);
    }

    @Transactional
    public TemplateResponse update(Long id, UpdateTemplateRequest req, User owner) {
        validateRegex(req.cnRegex, "CN");
        validateRegex(req.sanRegex, "SAN");
        if (req.ttlDays <= 0) throw new IllegalArgumentException("ttlDays mora biti > 0");

        var entity = repo.findByIdAndOwner(id, owner)
                .orElseThrow(() -> new IllegalArgumentException("Šablon nije pronađen"));

        var issuer = certRepo.findById(req.issuerId)
                .orElseThrow(() -> new IllegalArgumentException("Issuer ne postoji"));
        ensureIssuerIsValidCA(issuer);
        // ensureIssuerBelongsToOwnersChain(issuer, owner);

        entity.setName(req.name);
        entity.setIssuer(issuer);
        entity.setCnRegex(emptyToNull(req.cnRegex));
        entity.setSanRegex(emptyToNull(req.sanRegex));
        entity.setTtlDays(req.ttlDays);
        entity.setKeyUsage(mapKeyUsage(req.keyUsage));
        entity.setExtendedKeyUsage(mapExtKeyUsage(req.extendedKeyUsage));
        entity.setUpdatedAt(LocalDateTime.now());

        return toResponse(entity);
    }

    @Transactional
    public void delete(Long id, User owner) {
        var entity = repo.findByIdAndOwner(id, owner)
                .orElseThrow(() -> new IllegalArgumentException("Šablon nije pronađen"));
        repo.delete(entity);
    }

    // ===== helpers =====
    private void validateRegex(String regex, String field) {
        if (regex == null || regex.isBlank()) return;
        try { java.util.regex.Pattern.compile(regex); }
        catch (Exception e) { throw new IllegalArgumentException(field + " regex nije validan"); }
    }

    private void ensureIssuerIsValidCA(CertificateModel issuer) {
        // 1) revoked?
        if (Boolean.TRUE.equals(issuer.isRevoked())) {
            throw new IllegalArgumentException("Issuer je povučen (revoked)");
        }

        // 2) vreme važenja (sada je unutar [notBefore, notAfter])?
        var now = java.time.LocalDateTime.now();
        boolean inValidity = (issuer.getNotBefore() == null || !now.isBefore(issuer.getNotBefore())) &&
                (issuer.getNotAfter()  == null || !now.isAfter(issuer.getNotAfter()));
        if (!inValidity) {
            throw new IllegalArgumentException("Issuer nije trenutno važeći (van perioda važenja)");
        }

        // 3) iz X509: BasicConstraints i (opciono) KeyUsage.keyCertSign
        java.security.cert.X509Certificate x509;
        try {
            x509 = com.info_security.is.crypto.PemUtil.pemToCert(issuer.getCertificatePem());
        } catch (Exception e) {
            throw new IllegalArgumentException("Issuer sertifikat je nevalidan (PEM/X509)", e);
        }

        boolean isCa = x509.getBasicConstraints() >= 0; // CA (ROOT/Intermediate) ako je >= 0
        if (!isCa) {
            throw new IllegalArgumentException("Issuer nije CA sertifikat (BasicConstraints)");
        }

        // KeyUsage[5] == keyCertSign (ako je ekstenzija prisutna)
        boolean[] ku = x509.getKeyUsage();
        if (ku != null && !(ku.length > 5 && ku[5])) {
            throw new IllegalArgumentException("Issuer nema keyCertSign dozvolu u KeyUsage");
        }
    }


    private String emptyToNull(String s) { return (s == null || s.isBlank()) ? null : s; }

    private List<TemplateKeyUsage> mapKeyUsage(List<String> list) {
        return list.stream().map(v -> TemplateKeyUsage.valueOf(v)).toList();
    }
    private List<TemplateEKU> mapExtKeyUsage(List<String> list) {
        return list.stream().map(v -> TemplateEKU.valueOf(v)).toList();
    }

    private TemplateResponse toResponse(CertificateTemplate e) {
        var dto = new TemplateResponse();
        dto.id = e.getId();
        dto.name = e.getName();
        dto.issuerId = e.getIssuer().getId();
        dto.cnRegex = e.getCnRegex();
        dto.sanRegex = e.getSanRegex();
        dto.ttlDays = e.getTtlDays();
        dto.keyUsage = e.getKeyUsage().stream().map(Enum::name).toList();
        dto.extendedKeyUsage = e.getExtendedKeyUsage().stream().map(Enum::name).toList();
        dto.ownerUserId = e.getOwner().getId();
        dto.createdAt = e.getCreatedAt();
        dto.updatedAt = e.getUpdatedAt();
        return dto;
    }

}
