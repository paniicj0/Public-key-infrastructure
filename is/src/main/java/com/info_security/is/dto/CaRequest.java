package com.info_security.is.dto;

import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class CaRequest {
    @NotNull
    private Long issuerId;

    @NotNull @Valid
    private SubjectDto subject;

    @Min(1) @Max(1825)
    private int validityDays;

    private Integer keySize;   // default 4096

}
