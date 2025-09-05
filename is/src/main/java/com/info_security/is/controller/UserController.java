package com.info_security.is.controller;

import com.info_security.is.model.Activation;
import com.info_security.is.service.ActivationService;
import com.info_security.is.service.UserService;
import jakarta.persistence.EntityNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;

@Controller
public class UserController {

    @Autowired
    private UserService userService;

    @Autowired
    private ActivationService activationService;

    @Autowired
    private PasswordEncoder passwordEncoder;


    @PutMapping("/verify/users/{userId}")
    public ResponseEntity<String> verifyUserAccount(@PathVariable Long userId) {
        try {
            Activation activation= activationService.getActivationByUserId(userId);

            // check if activation is expired
            if (activation.isExpired()) {
                return new ResponseEntity<>("Activation link has expired.", HttpStatus.BAD_REQUEST);
            }
            userService.verifyUser(userId);
            return new ResponseEntity<>("User successfully verified.", HttpStatus.OK);
        } catch (EntityNotFoundException e) {
            return new ResponseEntity<>("User not found.", HttpStatus.NOT_FOUND);
        }
    }
}
