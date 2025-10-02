package com.info_security.is.dto;

import jakarta.validation.constraints.*;
import java.util.List;

public class UpdateTemplateRequest {
    @NotBlank @Size(max = 128)
    public String name;

    @NotNull
    public Long issuerId;

    @Size(max = 512)
    public String cnRegex;

    @Size(max = 512)
    public String sanRegex;

    @NotNull @Positive
    public Integer ttlDays;

    @NotNull @Size(min = 1)
    public List<String> keyUsage;

    @NotNull @Size(min = 1)
    public List<String> extendedKeyUsage;
}
