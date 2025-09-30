package com.info_security.is.controller;

import com.info_security.is.model.User;
import com.info_security.is.repository.UserRepository;
import com.info_security.is.verification.TokenVerify;
import io.jsonwebtoken.ExpiredJwtException;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authManager;
    private final TokenVerify tokens;
    private final UserDetailsService userDetailsService;
    private final UserRepository userRepository; // <<< dodaj

    record LoginReq(String username, String password) {}
    record RefreshReq(String refreshToken) {}
    record TokensWithRoleResp(String accessToken, String refreshToken, String role) {}
    record TokensResp(String accessToken, String refreshToken) {}
    record ErrorResp(String error) {}
    private static ErrorResp err(String m){ return new ErrorResp(m); }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginReq req) {
        Authentication auth = authManager.authenticate(
                new UsernamePasswordAuthenticationToken(req.username(), req.password())
        );

        UserDetails ud = (UserDetails) auth.getPrincipal();

        // subject za JWT: koristi ono što ima smisla, uz fallback na req.username()
        String subject = (ud.getUsername() != null && !ud.getUsername().isBlank())
                ? ud.getUsername()
                : req.username();

        // napravi tokene sa ispravnim subject-om
        String access  = tokens.generateAccessToken(subject);
        String refresh = tokens.generateRefreshToken(subject);

        // rolu čitamo DIREKTNO iz baze po subject-u (emailu)
        String role = userRepository.findByEmail(subject)
                .map(u -> u.getRole().name())     // "ADMIN" | "CA" | "USER"
                .orElseThrow(() -> new UsernameNotFoundException("No user " + subject));

        return ResponseEntity.ok(new TokensWithRoleResp(access, refresh, role));
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@RequestBody RefreshReq req) {
        try {
            String refreshJwt = stripBearer(req.refreshToken());
            if (refreshJwt == null || !tokens.isRefresh(refreshJwt)) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(err("Not a refresh token"));
            }
            String username = tokens.getUsername(refreshJwt);
            if (username == null || username.isBlank()) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(err("Invalid refresh"));
            }

            UserDetails ud = userDetailsService.loadUserByUsername(username);
            String newAccess = tokens.generateAccessToken(ud.getUsername());
            return ResponseEntity.ok(new TokensResp(newAccess, null));

        } catch (ExpiredJwtException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(err("Refresh expired"));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(err("Invalid refresh"));
        }
    }

    private static String stripBearer(String v) {
        if (v == null) return null;
        return v.startsWith("Bearer ") ? v.substring(7) : v;
    }
}
