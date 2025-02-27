package com.esprit.project.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;

@Component
public class JwtUtil {

    private static final Logger logger = LoggerFactory.getLogger(JwtUtil.class);

    //private static final String SECRET_KEY = "6v+Kj7r/4A+6n6J9u5lFjQ=jihedbouaziziaminebouallaguimohammedchehida="; // Use a strong secret
    private static final long EXPIRATION_TIME = 60 * 60 * 1000; // 1 hour in milliseconds

    private static final SecretKey key = Keys.secretKeyFor(SignatureAlgorithm.HS512);

    // ✅ Generate JWT Token
    public String generateToken(String username) {
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(key, SignatureAlgorithm.HS512) // Updated signature method
                .compact();
    }

    // ✅ Extract Username from JWT
    public String extractUsername(String token) {
        return parseClaims(token).getSubject();
    }

    // ✅ Validate JWT Token
    public boolean validateToken(String token, String username) {
        try {
            final String extractedUsername = extractUsername(token);
            return extractedUsername.equals(username) && !isTokenExpired(token);
        } catch (JwtException | IllegalArgumentException e) {
            logger.error("JWT validation error: {}", e.getMessage());
            return false; // Invalid token
        }
    }

    // ✅ Check Token Expiry
    private boolean isTokenExpired(String token) {
        return parseClaims(token).getExpiration().before(new Date());
    }

    // ✅ Parse Claims (Refactored to avoid redundant parsing)
    private Claims parseClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}