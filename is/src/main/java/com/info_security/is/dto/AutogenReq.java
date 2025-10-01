package com.info_security.is.dto;

public record AutogenReq(
        Long issuerId,
        Integer validityDays,
        Integer keySize,
        SubjectDtoRecord subject,
        Boolean downloadP12,        // ako true, odmah vraćamo p12 (attachment)
        String p12Password          // obavezno ako downloadP12 = true
) {}
