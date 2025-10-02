package com.info_security.is.dto;

import jakarta.validation.constraints.*;
import java.util.List;

public class CreateTemplateRequest {
    @NotBlank @Size(max = 128)
    public String name;

    @NotNull
    public Long issuerId;  // CA issuer

    @Size(max = 512)
    public String cnRegex;

    @Size(max = 512)
    public String sanRegex;

    @NotNull @Positive
    public Integer ttlDays; // maksimalno trajanje

    @NotNull @Size(min = 1)
    public List<String> keyUsage; // vrednosti iz TemplateKeyUsage

    @NotNull @Size(min = 1)
    public List<String> extendedKeyUsage; // vrednosti iz TemplateExtendedKeyUsage
}

