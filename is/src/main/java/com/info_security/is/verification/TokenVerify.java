package com.info_security.is.verification;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;


@Component
public class TokenVerify {

    @Value("PKI")
    private String appName;

    @Value("someSecretKeyHereThatIsLongEnoughsomeSecretKeyHereThatIsLongEnoughsomeSecretKeyHereThatIsLongEnough")
    public String secret;
    SecretKey key = Keys.secretKeyFor(SignatureAlgorithm.HS512);

    @Value("9900000")
    private Long expiresIn;

    @Value("Authorization")
    private String authorizationHeader;

    private static final String audienceWeb="web";

    private SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS512;


    public String generateToken(String username) {
        return Jwts.builder()
                .setIssuer("PKI") // Set your app name
                .setSubject(username)
                .setAudience(audienceWeb)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(generateExpirationDate())
                .signWith(Keys.hmacShaKeyFor(secret.getBytes()), signatureAlgorithm) // Use proper key
                .compact();
    }

    private Date generateExpirationDate() {
        return new Date(System.currentTimeMillis() + expiresIn);
    }

    public String getUsernameFromToken(String token) {
        String username;
        try {
            final Claims claims = getAllClaimsFromToken(token);
            username = claims.getSubject();
        } catch (ExpiredJwtException ex) {
            throw ex;
        } catch (Exception e) {
            username = null;
        }
        return username;
    }

    private Claims getAllClaimsFromToken(String token) {
        Claims claims;
        try {
            claims = Jwts.parserBuilder()
                    .setSigningKey(Keys.hmacShaKeyFor(secret.getBytes())) // Use proper key
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (ExpiredJwtException ex) {
            throw ex;
        } catch (Exception e) {
            claims = null;
        }
        return claims;
    }

    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = getUsernameFromToken(token);
        return username != null ;//&& username.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }
    //ovaj deo je obrisan jer se vreme ne izvlaci dobro iz tokena
    /*private Boolean isTokenExpired(String token) {
        final Date expiration = getExpirationDateFromToken(token);
        return expiration != null && expiration.before(new Date());
    }

    private Date getExpirationDateFromToken(String token) {
        Date expiration;
        try {
            final Claims claims = getAllClaimsFromToken(token);
            expiration = claims.getExpiration();
        } catch (ExpiredJwtException ex) {
            throw ex;
        } catch (Exception e) {
            expiration = null;
        }
        return expiration;
    }*/


}

