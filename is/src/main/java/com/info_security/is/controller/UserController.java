package com.info_security.is.controller;

import com.info_security.is.dto.AdminDto;
import com.info_security.is.dto.CaDto;
import com.info_security.is.dto.RegisterUserDto;
import com.info_security.is.dto.UserDto;
import com.info_security.is.enums.UserRole;
import com.info_security.is.model.*;
import com.info_security.is.repository.ActivationRepository;
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
import java.time.Instant;
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

    @Autowired
    private ActivationRepository activationRepository;

    @CrossOrigin(origins = "http://localhost:4200")
    @GetMapping("/activation/verify")
    @Transactional
    public ResponseEntity<String> verifyUserAccount(@RequestParam("token") String rawToken) {
        String tokenHash = activationService.sha256Hex(rawToken);

        Activation activation = activationRepository.findByTokenHash(tokenHash)
                .orElseThrow(() -> new EntityNotFoundException("Invalid activation token"));

        if (activation.isUsed()) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body("Activation link already used.");
        }
        if (activation.isExpired()) {
            return ResponseEntity.badRequest().body("Activation link has expired.");
        }

        userService.verifyUser(activation.getUser().getId());
        activation.setUsedAt(LocalDateTime.now()); // ✅ ne LocalDateTime.from(Instant.now())
        activationRepository.save(activation);     // ili delete(activation) za one-shot

        return ResponseEntity.ok("User successfully verified.");
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
        user.setActive(false);
        user.setOrganization(org);

        userService.saveUser(user); // zbog cascade će sačuvati i activation

        // 4) Pošalji aktivacioni e-mail
        activationService.createActivationAndSendEmail(user);

        return new ResponseEntity<>(user.getId(), HttpStatus.CREATED);
    }

    @PostMapping(value = "/createCA/users", name = "create CA user")
    public ResponseEntity<Long> createCAUser(@RequestBody RegisterUserDto dto,
                                             @RequestParam("type") UserRole role)
            throws MessagingException, UnsupportedEncodingException {

        Organization org = organizationService.findOrCreateByName(dto.getOrganizationName());

        User user = new User();
        user.setEmail(dto.getEmail());
        user.setPassword(passwordEncoder.encode(dto.getPassword()));
        user.setFirstName(dto.getFirstName());
        user.setLastName(dto.getLastName());
        user.setRole(role);
        user.setActive(false);
        user.setOrganization(org);

        userService.saveUser(user); // zbog cascade će sačuvati i activation

        activationService.createActivationAndSendEmail(user);

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

    public record LoginResponse(String token, String role) {}

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody AuthenticationRequest req) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(req.getUsername(), req.getPassword())
        );

        User user = (User) authentication.getPrincipal();

        if (!user.isActive()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null);
        }

        String jwt = tokenUtils.generateToken(user.getEmail());
        return ResponseEntity.ok(new LoginResponse(jwt, user.getRole().toString()));
    }


    @GetMapping("/role")
    public ResponseEntity<String> getRole() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        User user = (User) authentication.getPrincipal();
        return ResponseEntity.ok(user.getRole().toString());
    }
}
