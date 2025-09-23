package com.info_security.is.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class SubjectDto {
    @NotBlank
    @Size(max = 255)
    private String cn;     // Common Name

    @Size(max = 255)
    private String o;

    @Size(max = 255)
    private String ou;

    @Pattern(regexp = "^[A-Z]{2}$", message = "Country must be 2-letter ISO code (e.g., RS, US)")
    private String c;      // Country (2 slova), opcionalno

    @Size(max = 255)
    private String e;

}
