package com.info_security.is.controller;

import com.info_security.is.dto.AdminDto;
import com.info_security.is.dto.CaDto;
import com.info_security.is.dto.UserDto;
import com.info_security.is.enums.UserRole;
import com.info_security.is.model.Activation;
import com.info_security.is.model.Admin;
import com.info_security.is.model.CA;
import com.info_security.is.model.User;
import com.info_security.is.service.ActivationService;
import com.info_security.is.service.UserService;
import jakarta.mail.MessagingException;
import jakarta.persistence.EntityNotFoundException;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Optional;

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

    @Transactional
    // 1.1 Registracija korisnika //create user
    @PostMapping(value = "/register/users", name = "register user")// api/users?type=GUEST
    public ResponseEntity<Long> registerUser(@RequestBody UserDto userDTO) throws MessagingException, UnsupportedEncodingException {

        User user = new User((UserDto) userDTO);

        user.setRole(UserRole.USER);
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        userService.saveUser(user);

        // Kreiraj aktivaciju
        Activation activation = new Activation();
        activation.setUser(user);  // poveži aktivaciju sa korisnikom
        activation.setCreationDate(LocalDateTime.now());  // postavi datum kreacije
        activation.setExpirationDate(LocalDateTime.now().plusHours(24));  // postavi datum isteka

        user.setActivation(activation);

        // Spasi korisnika (što će automatski sačuvati aktivaciju zbog cascade)
        userService.saveUser(user);

        // Pošaljite aktivacioni mail
        activationService.sendActivationEmail(user);

        return new ResponseEntity<>(user.getId(), HttpStatus.CREATED);
    }

    @GetMapping(value = "/users/byUsername/{username}")
    public ResponseEntity<?> getUserAccountByEmail(@PathVariable String username) {
        Optional<User> userOptional = userService.findByEmail(username);

        System.out.println(userOptional);

        // Proverite da li Optional SADRŽI usera
        if (!userOptional.isPresent()) {
            return new ResponseEntity<>(null, HttpStatus.NOT_FOUND);
        }
        // Izvucite User objekat iz Optionala
        User user = userOptional.get();

        // Provera tipa korisnika pre kastovanja
        if (user.getRole() == UserRole.CA && user instanceof CA) {
            CA ca = (CA) user;
            return new ResponseEntity<>(new CaDto(ca), HttpStatus.OK);
        } else if (user.getRole() == UserRole.ADMIN && user instanceof Admin) {
            Admin admin = (Admin) user;
            return new ResponseEntity<>(new AdminDto(admin), HttpStatus.OK);
        } else if (user.getRole() == UserRole.USER && user instanceof User) {
            User od = (User) user;
            return new ResponseEntity<>(new UserDto(od), HttpStatus.OK);
        }

        // Ako nije moguće odrediti tip korisnika
        return new ResponseEntity<>("Unsupported user role or type", HttpStatus.BAD_REQUEST);
    }
}
