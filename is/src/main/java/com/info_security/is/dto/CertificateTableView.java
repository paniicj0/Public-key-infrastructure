package com.info_security.is.dto;

import com.info_security.is.model.CertificateModel;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter
@Setter
public class CertificateTableView {
    private Long id;
    private String type;
    private String serialNumber;
    private LocalDateTime notBefore;
    private LocalDateTime notAfter;
    private boolean revoked;
    private String revocationReason;
    private LocalDateTime revokedAt;

    public CertificateTableView(CertificateModel m) {
        this.id = m.getId();
        this.type = m.getType().name();
        this.serialNumber = m.getSerialNumber();
        this.notBefore = m.getNotBefore();
        this.notAfter = m.getNotAfter();
        this.revoked = m.isRevoked();
        this.revocationReason = m.getRevocationReason() != null ? m.getRevocationReason().name() : null;
        this.revokedAt = m.getRevokedAt();
    }
}
