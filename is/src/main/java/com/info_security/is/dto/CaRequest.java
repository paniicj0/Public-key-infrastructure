package com.info_security.is.dto;

import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter

public class CaRequest {
    @NotNull
    private Long issuerId;           // CA koji potpisuje
    @NotNull @Valid
    public SubjectDto subject;
    @Min(1) @Max(1825)
    private int validityDays;

    public ExtensionsDto extensions; // CA=true
    public String keyAlg;
    public Integer keySize;
    public String sigAlg;
}
