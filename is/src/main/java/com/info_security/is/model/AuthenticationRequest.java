package com.info_security.is.model;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;


@Getter
@Setter
public class AuthenticationRequest {

    @Email
    @Size(min = 5, max = 50)
    private String username;
    private String password;

    public AuthenticationRequest() {super();}

    public AuthenticationRequest(String username, String password) {
        this.setUsername(username);
        this.setPassword(password);
    }
}
