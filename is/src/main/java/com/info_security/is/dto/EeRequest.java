package com.info_security.is.dto;


import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class EeRequest {
    @NotNull
    private Long issuerId;
    @NotNull @Valid
    public SubjectDto subject;
    @Min(1) @Max(825)
    private int validityDays;
    public ExtensionsDto extensions; // CA=false; EKU/KeyUsage po svrsi
    public String keyAlg;
    public Integer keySize;
    public String sigAlg;
    public String pkcs10CsrPem; // ili null ako generišeš ključ server-side
    private Long templateId;

}
