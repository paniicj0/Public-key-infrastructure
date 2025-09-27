package com.info_security.is.dto;

import lombok.*;

@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class UserResponseDto {
    private Long id;
    private String email;
    private String firstName;
    private String lastName;
    private String role;              // "USER", "ADMIN", "CA", ...
    private String organizationName;  // <— OVO NAM TREBA
}


