package com.info_security.is.dto;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class RegisterUserDto {
    private String email;
    private String password;
    private String firstName;
    private String lastName;
    private String organizationName;

}