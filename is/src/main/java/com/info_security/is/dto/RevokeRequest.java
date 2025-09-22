package com.info_security.is.dto;

import com.info_security.is.enums.RevocationReason;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class RevokeRequest {
    @NotNull
    private RevocationReason reason;

}