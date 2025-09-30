package com.info_security.is.verification;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class TokenVerify {

    // Preferiraj base64; ako nije zadat, koristi raw
    @Value("${app.jwt.secret.base64:}")
    private String secretB64;

    @Value("${app.jwt.secret.raw:}")
    private String secretRaw;

    @Value("${app.jwt.access.expires-in-ms:900000}")
    private long accessExpiresInMs;

    @Value("${app.jwt.refresh.expires-in-ms:1209600000}")
    private long refreshExpiresInMs;

    private static final String CLAIM_TYPE = "typ";
    private static final String TYPE_ACCESS = "access";
    private static final String TYPE_REFRESH = "refresh";

    private SecretKey cachedKey;

    @PostConstruct
    void init() {
        this.cachedKey = resolveKey();
        // Informativno logovanje (nije obavezno)
        int bitLen = this.cachedKey.getEncoded().length * 8;
        if (bitLen < 512) {
            throw new IllegalStateException("JWT key too short for HS512: " + bitLen + " bits. Provide >= 512 bits.");
        }
        System.out.println("[JWT] HS512 key is OK (" + bitLen + " bits).");
    }

    private SecretKey resolveKey() {
        if (secretB64 != null && !secretB64.isBlank()) {
            byte[] bytes = Decoders.BASE64.decode(secretB64);
            return Keys.hmacShaKeyFor(bytes);
        }
        if (secretRaw != null && !secretRaw.isBlank()) {
            // ako baš koristiš raw string, neka bude 64+ bajta
            byte[] bytes = secretRaw.getBytes(StandardCharsets.UTF_8);
            return Keys.hmacShaKeyFor(bytes);
        }
        // ako ništa nije zadato, generiši i ispiši base64 da korisnik može da prekopira u properties
        SecretKey k = Keys.secretKeyFor(SignatureAlgorithm.HS512);
        String generated = Encoders.BASE64.encode(k.getEncoded());
        System.err.println("[JWT] No key provided. Generated one-time Base64 key below.\n" +
                "Put this in application.properties:\napp.jwt.secret.base64=" + generated);
        return k;
    }

    public String generateAccessToken(String username) {
        return Jwts.builder()
                .setIssuer("PKI")
                .setSubject(username)
                .claim(CLAIM_TYPE, TYPE_ACCESS)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + accessExpiresInMs))
                .signWith(cachedKey, SignatureAlgorithm.HS512)
                .compact();
    }

    public String generateRefreshToken(String username) {
        return Jwts.builder()
                .setIssuer("PKI")
                .setSubject(username)
                .claim(CLAIM_TYPE, TYPE_REFRESH)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + refreshExpiresInMs))
                .signWith(cachedKey, SignatureAlgorithm.HS512)
                .compact();
    }

    public Claims parse(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(cachedKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public String getUsername(String token) { return parse(token).getSubject(); }
    public boolean isAccess(String token)   { return TYPE_ACCESS.equals(parse(token).get(CLAIM_TYPE)); }
    public boolean isRefresh(String token)  { return TYPE_REFRESH.equals(parse(token).get(CLAIM_TYPE)); }
}
