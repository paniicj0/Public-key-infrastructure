package com.info_security.is.controller;

import com.info_security.is.dto.AdminDto;
import com.info_security.is.dto.CaDto;
import com.info_security.is.dto.RegisterUserDto;
import com.info_security.is.dto.UserDto;
import com.info_security.is.enums.UserRole;
import com.info_security.is.model.*;
import com.info_security.is.service.ActivationService;
import com.info_security.is.service.OrganizationService;
import com.info_security.is.service.UserService;
import com.info_security.is.verification.TokenVerify;
import jakarta.mail.MessagingException;
import jakarta.persistence.EntityNotFoundException;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.io.UnsupportedEncodingException;
import java.time.LocalDateTime;
import java.util.Optional;

@Controller
@RequestMapping("/api")
public class UserController {

    @Autowired
    private UserService userService;

    @Autowired
    private ActivationService activationService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private OrganizationService organizationService;

    @Autowired
    private TokenVerify tokenUtils;

    @Autowired
    private AuthenticationManager authenticationManager;

    @CrossOrigin(origins = "http://localhost:4200")
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
    @PostMapping(value = "/register/users", name = "register user")
    public ResponseEntity<Long> registerUser(@RequestBody RegisterUserDto dto,
                                             @RequestParam("type") UserRole role)
            throws MessagingException, UnsupportedEncodingException {

        // 1) Organizacija po imenu (find or create)
        Organization org = organizationService.findOrCreateByName(dto.getOrganizationName());

        // 2) Napravi korisnika i popuni polja
        User user = new User();
        user.setEmail(dto.getEmail());
        user.setPassword(passwordEncoder.encode(dto.getPassword()));
        user.setFirstName(dto.getFirstName());
        user.setLastName(dto.getLastName());
        user.setRole(role);
        user.setActive(false);              // preporuka: neaktivan dok ne potvrdi mail
        user.setOrganization(org);          // <-- ključni deo: vežemo na organizaciju

        userService.saveUser(user);

        // 3) Kreiraj aktivaciju
        Activation activation = new Activation();
        activation.setUser(user);
        activation.setCreationDate(LocalDateTime.now());
        activation.setExpirationDate(LocalDateTime.now().plusHours(24));
        user.setActivation(activation);

        userService.saveUser(user); // zbog cascade će sačuvati i activation

        // 4) Pošalji aktivacioni e-mail
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

    @PostMapping(value = "/login", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> createAuthenticationToken(
            @RequestBody AuthenticationRequest authenticationRequest, HttpServletResponse response) {
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                authenticationRequest.getUsername(), authenticationRequest.getPassword()));

        // Set the authentication in the SecurityContextHolder
        SecurityContextHolder.getContext().setAuthentication(authentication);

        User user = (User) authentication.getPrincipal();

        if (!user.isActive()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("User is not verified");
        }

        String jwt = tokenUtils.generateToken(user.getEmail());
        return ResponseEntity.ok(jwt);

    }

    @GetMapping("/role")
    public ResponseEntity<String> getRole() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        User user = (User) authentication.getPrincipal();
        return ResponseEntity.ok(user.getRole().toString());
    }
}
