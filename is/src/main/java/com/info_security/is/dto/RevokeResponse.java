package com.info_security.is.dto;

import com.info_security.is.enums.RevocationReason;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class RevokeResponse {
    private Long id;
    private boolean revoked;
    private RevocationReason reason;
    private String revokedAt;

    public RevokeResponse() {}

    public RevokeResponse(Long id, boolean revoked, RevocationReason reason, String revokedAt) {
        this.id = id;
        this.revoked = revoked;
        this.reason = reason;
        this.revokedAt = revokedAt;
    }

}
