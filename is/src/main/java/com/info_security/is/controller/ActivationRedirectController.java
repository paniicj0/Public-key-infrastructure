package com.info_security.is.controller;

import com.info_security.is.service.UserService;
import jakarta.persistence.EntityNotFoundException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.net.URI;
@RestController
@RequestMapping("/api/activation")
public class ActivationRedirectController {

    private final String frontendLoginUrl;
    private final UserService userService;

    public ActivationRedirectController(
            @Value("${app.frontend.login-url:http://localhost:4200/login}") String frontendLoginUrl,
            UserService userService) {
        this.frontendLoginUrl = frontendLoginUrl;
        this.userService = userService;
    }

    @GetMapping("/verify/{userId}")
    public ResponseEntity<Void> verifyByLink(@PathVariable Long userId) {
        try {
            userService.verifyByUserId(userId);
            return ResponseEntity.status(HttpStatus.FOUND)
                    .location(URI.create(frontendLoginUrl + "?verified=1"))
                    .build();
        } catch (EntityNotFoundException e) {
            return ResponseEntity.status(HttpStatus.FOUND)
                    .location(URI.create(frontendLoginUrl + "?verified=0&reason=user_not_found"))
                    .build();
        } catch (IllegalStateException e) {
            return ResponseEntity.status(HttpStatus.FOUND)
                    .location(URI.create(frontendLoginUrl + "?verified=0&reason=expired"))
                    .build();
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.FOUND)
                    .location(URI.create(frontendLoginUrl + "?verified=0&reason=error"))
                    .build();
        }
    }
}
