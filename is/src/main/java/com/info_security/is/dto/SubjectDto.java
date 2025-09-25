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
    public String commonName;   // CN
    @Size(max = 255)
    public String organization; // O
    @Size(max = 255)
    public String orgUnit;      // OU
    @Pattern(regexp = "^[A-Z]{2}$", message = "Country must be 2-letter ISO code (e.g., RS, US)")
    public String country;      // C (2 slova)

    public String state;        // ST
    public String locality;     // L
    public String email;        // emailAddress
}
