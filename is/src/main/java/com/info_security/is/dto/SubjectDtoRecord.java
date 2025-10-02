package com.info_security.is.dto;

public record SubjectDtoRecord(
        String commonName, String organization, String orgUnit,
        String country, String email
) {}
