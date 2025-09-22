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
    private SubjectDto subject;

    @Min(1) @Max(825)
    private int validityDays;

    private boolean packPkcs12 = true;
    @Size(min = 4, max = 128)
    private String pkcs12Password = "changeit";

    private Integer keySize;     // default 2048

}
