package com.info_security.is.dto;

import com.info_security.is.enums.RevocationReason;
import com.info_security.is.model.CertificateModel;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class CertificateResponse {
    private Long id;
    private String type;       // ROOT, CA, EE
    private String serial;
    private String notBefore;
    private String notAfter;
    private Long issuerId;

    private boolean revoked;
    private String revocationReason;
    private String revokedAt;

    public CertificateResponse() {}

    public CertificateResponse(Long id, String type, String serial, String notBefore,
                               String notAfter, Long issuerId,
                               boolean revoked, String revocationReason, String revokedAt) {
        this.id = id;
        this.type = type;
        this.serial = serial;
        this.notBefore = notBefore;
        this.notAfter = notAfter;
        this.issuerId = issuerId;
        this.revoked = revoked;
        this.revocationReason = revocationReason;
        this.revokedAt = revokedAt;
    }

    public CertificateResponse(CertificateModel saved) {
        if (saved == null) return;
        this.id = saved.getId();
        this.type = saved.getType() != null ? saved.getType().name() : null;
        this.serial = saved.getSerialNumber();
        this.notBefore = saved.getNotBefore() != null ? saved.getNotBefore().toString() : null;
        this.notAfter = saved.getNotAfter() != null ? saved.getNotAfter().toString() : null;
        this.issuerId = saved.getIssuer() != null ? saved.getIssuer().getId() : null;

        this.revoked = saved.isRevoked();
        this.revocationReason = saved.getRevocationReason() != null
                ? saved.getRevocationReason().name()
                : null;
        this.revokedAt = saved.getRevokedAt() != null
                ? saved.getRevokedAt().toString()
                : null;
    }
}
