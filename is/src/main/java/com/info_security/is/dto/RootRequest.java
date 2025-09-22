package com.info_security.is.dto;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class RootRequest {
    @NotNull @Valid
    private SubjectDto subject;

    @Min(1) @Max(3650)
    private int validityDays;

    private Integer keySize;


}
